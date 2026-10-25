import AppKit
import ApplicationServices
import Foundation

struct Request: Decodable {
  let action: String
  let expectedURL: String?
  let expectedDOMId: String?
  let text: String?
}
struct InputFailure: Error { let message: String }
func fail(_ message: String) throws -> Never { throw InputFailure(message: message) }
func emit(_ object: [String: Any]) {
  if let data = try? JSONSerialization.data(withJSONObject: object), let text = String(data: data, encoding: .utf8) { print(text) }
}
func attribute(_ element: AXUIElement, _ name: String) -> CFTypeRef? {
  var value: CFTypeRef?
  guard AXUIElementCopyAttributeValue(element, name as CFString, &value) == .success else { return nil }
  return value
}
func elementAttribute(_ element: AXUIElement, _ name: String) -> AXUIElement? {
  guard let value = attribute(element, name), CFGetTypeID(value) == AXUIElementGetTypeID() else { return nil }
  return unsafeBitCast(value, to: AXUIElement.self)
}
func stringAttribute(_ element: AXUIElement, _ name: String) -> String? {
  guard let value = attribute(element, name) else { return nil }
  if let text = value as? String { return text }
  if let url = value as? URL { return url.absoluteString }
  return nil
}
var initialFocusedElement: AXUIElement?
func checkedTarget(_ request: Request) throws -> pid_t {
  guard AXIsProcessTrusted(), CGPreflightPostEventAccess() else { try fail("NATIVE_INPUT_PERMISSION_REQUIRED: macOS Accessibility permission is required; no events sent") }
  guard let app = NSWorkspace.shared.frontmostApplication, app.bundleIdentifier == "com.google.Chrome" else { try fail("NATIVE_INPUT_FOCUS_CHANGED: Google Chrome is not the foreground application") }
  let axApp = AXUIElementCreateApplication(app.processIdentifier)
  guard let window = elementAttribute(axApp, kAXFocusedWindowAttribute),
        let document = stringAttribute(window, kAXDocumentAttribute),
        let expectedURL = request.expectedURL, document == expectedURL,
        expectedURL.hasPrefix("https://") || expectedURL.hasPrefix("http://") else { try fail("NATIVE_INPUT_TARGET_CHANGED: focused Chrome document does not match the requested page") }
  guard let focused = elementAttribute(axApp, kAXFocusedUIElementAttribute),
        let role = stringAttribute(focused, kAXRoleAttribute),
        ["AXTextField", "AXTextArea", "AXComboBox"].contains(role) else { try fail("NATIVE_INPUT_FOCUS_CHANGED: the focused accessibility element is not an editable field") }
  // Address bars and extension popups can also have AXTextField roles. Require
  // a field inside page content, and keep the same AX element for this batch.
  var ancestor: AXUIElement? = focused
  var insideWebPage = false
  for _ in 0..<24 {
    guard let current = ancestor else { break }
    if stringAttribute(current, kAXRoleAttribute) == "AXWebArea" { insideWebPage = true; break }
    ancestor = elementAttribute(current, kAXParentAttribute)
  }
  guard insideWebPage else { try fail("NATIVE_INPUT_FOCUS_CHANGED: focus is in browser chrome, not page content") }
  if let initial = initialFocusedElement {
    guard CFEqual(initial, focused) else { try fail("NATIVE_INPUT_FOCUS_CHANGED: focused field changed during the batch") }
  } else { initialFocusedElement = focused }
  if let expected = request.expectedDOMId, !expected.isEmpty,
     let actual = stringAttribute(focused, "AXDOMIdentifier") ?? stringAttribute(focused, kAXIdentifierAttribute), !actual.isEmpty, actual != expected {
    try fail("NATIVE_INPUT_TARGET_CHANGED: focused field identifier changed")
  }
  return app.processIdentifier
}
let keyCodes: [Character: CGKeyCode] = ["a":0,"s":1,"d":2,"f":3,"h":4,"g":5,"z":6,"x":7,"c":8,"v":9,"b":11,"q":12,"w":13,"e":14,"r":15,"y":16,"t":17,"1":18,"2":19,"3":20,"4":21,"6":22,"5":23,"=":24,"9":25,"7":26,"-":27,"8":28,"0":29,"]":30,"o":31,"u":32,"[":33,"i":34,"p":35,"l":37,"j":38,"'":39,"k":40,";":41,"\\":42,",":43,"/":44,"n":45,"m":46,".":47," ":49,"`":50]
let shifted: [Character: Character] = ["_":"-","+":"=","!":"1","@":"2","#":"3","$":"4","%":"5","^":"6","&":"7","*":"8","(":"9",")":"0","{":"[","}":"]","|":"\\",":":";","\"":"'","<":",",">":".","?":"/","~":"`"]
func key(_ request: Request, _ code: CGKeyCode, flags: CGEventFlags = [], text: String? = nil) throws {
  let pid = try checkedTarget(request)
  guard let source = CGEventSource(stateID: .privateState),
        let down = CGEvent(keyboardEventSource: source, virtualKey: code, keyDown: true),
        let up = CGEvent(keyboardEventSource: source, virtualKey: code, keyDown: false) else { try fail("NATIVE_INPUT_EVENT_FAILED: could not create keyboard events") }
  down.flags = flags; up.flags = flags
  if let text = text {
    let utf16 = Array(text.utf16)
    utf16.withUnsafeBufferPointer { buffer in
      down.keyboardSetUnicodeString(stringLength: buffer.count, unicodeString: buffer.baseAddress)
      up.keyboardSetUnicodeString(stringLength: buffer.count, unicodeString: buffer.baseAddress)
    }
  }
  // Address Chrome's process directly; never post to the global keyboard tap.
  down.postToPid(pid)
  usleep(3000)
  up.postToPid(pid)
  usleep(7000)
}
var sent = 0
 do {
  guard let line = readLine(), line.utf8.count <= 65536 else { try fail("NATIVE_INPUT_INVALID_REQUEST") }
  let request = try JSONDecoder().decode(Request.self, from: Data(line.utf8))
  if request.action == "status" {
    emit(["ok": true, "accessibilityTrusted": AXIsProcessTrusted(), "canPostEvents": CGPreflightPostEventAccess()])
  } else {
    _ = try checkedTarget(request)
    switch request.action {
    case "clear":
      try key(request, 0, flags: .maskCommand)
      try key(request, 51)
    case "enter": try key(request, 36)
    case "text":
      guard let text = request.text, !text.isEmpty, text.count <= 16 else { try fail("NATIVE_INPUT_INVALID_TEXT: batches must contain 1 to 16 characters") }
      for char in text {
        if char == "\n" || char == "\r" { try key(request, 36) }
        else if char == "\t" { try key(request, 48) }
        else {
          let lower = Character(String(char).lowercased())
          let base = shifted[char] ?? lower
          let shift = shifted[char] != nil || (String(char) != String(char).lowercased())
          try key(request, keyCodes[base] ?? 0, flags: shift ? .maskShift : [], text: String(char))
        }
        sent += 1
      }
    default: try fail("NATIVE_INPUT_INVALID_ACTION")
    }
    emit(["ok": true, "characters": sent, "backend": "macOS-CGEventPostToPid"])
  }
} catch {
  let message = (error as? InputFailure)?.message ?? "NATIVE_INPUT_INVALID_REQUEST"
  emit(["ok": false, "error": message, "charactersSent": sent])
  exit(1)
}
