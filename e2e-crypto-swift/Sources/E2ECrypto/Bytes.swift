import Foundation

public enum E2EError: Error, CustomStringConvertible, Equatable {
    case invalidBase64
    case invalidSignature(String)
    case invalidKey(String)
    case decryptFailed(String)
    case replayOrExpired
    case tooManySkipped
    case notInitialised
    case cannotSend
    case invalidFormat(String)
    /// A group message arrived before its sender's key.
    case missingSenderKey(conversationId: String, senderId: String)

    public var description: String {
        switch self {
        case .invalidBase64: return "e2e-crypto: invalid base64"
        case .invalidSignature(let s): return s
        case .invalidKey(let s): return s
        case .decryptFailed(let s): return s
        case .replayOrExpired: return "Message key already used/expired (replay?) — rejecting"
        case .tooManySkipped: return "Too many skipped messages"
        case .notInitialised: return "E2EE identity not initialised"
        case .cannotSend: return "Session cannot send yet — wait for the first message from the initiator"
        case .invalidFormat(let s): return s
        case .missingSenderKey(let c, let s): return "No sender key from \(s) for \(c)"
        }
    }
}

/// Standard base64 with padding; decoding also accepts missing padding (same as the JS package).
public enum Base64 {
    public static func encode(_ data: Data) -> String { data.base64EncodedString() }

    public static func decode(_ string: String) throws -> Data {
        var s = string
        while s.hasSuffix("=") { s.removeLast() }
        if s.count % 4 == 1 { throw E2EError.invalidBase64 }
        s += String(repeating: "=", count: (4 - s.count % 4) % 4)
        guard let d = Data(base64Encoded: s) else { throw E2EError.invalidBase64 }
        return d
    }
}

extension Data {
    var b64: String { Base64.encode(self) }
    static func random(_ count: Int) -> Data {
        var g = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: 0...255, using: &g) })
    }
    var utf8String: String { String(decoding: self, as: UTF8.self) }
}

extension String {
    func unb64() throws -> Data { try Base64.decode(self) }
    var utf8Data: Data { Data(utf8) }
}

/// Constant-time comparison (length is not secret).
func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for (x, y) in zip(a, b) { diff |= x ^ y }
    return diff == 0
}

// MARK: - Minimal ordered JSON writer
// The wire format needs "e2e" to be the first key (the JS side detects envelopes by prefix),
// and JSONSerialization / JSONEncoder don't guarantee key order.

indirect enum JSON {
    case string(String)
    case int(Int)
    case bool(Bool)
    case null
    case array([JSON])
    case object([(String, JSON)])

    var text: String {
        switch self {
        case .string(let s): return JSON.quote(s)
        case .int(let i): return String(i)
        case .bool(let b): return b ? "true" : "false"
        case .null: return "null"
        case .array(let a): return "[" + a.map(\.text).joined(separator: ",") + "]"
        case .object(let kv): return "{" + kv.map { JSON.quote($0.0) + ":" + $0.1.text }.joined(separator: ",") + "}"
        }
    }

    static func quote(_ s: String) -> String {
        var out = "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if u.value < 0x20 { out += String(format: "\\u%04x", u.value) } else { out.unicodeScalars.append(u) }
            }
        }
        return out + "\""
    }

    static func opt(_ s: String?) -> JSON { s.map { .string($0) } ?? .null }
}

/// JSONSerialization numbers are NSNumber on Apple platforms but may be Int/Double on Linux.
func anyInt(_ v: Any?) -> Int? {
    if let i = v as? Int { return i }
    if let d = v as? Double { return Int(d) }
    if let n = v as? NSNumber { return n.intValue }
    return nil
}

/// Parsing helpers over JSONSerialization output.
enum JSONRead {
    static func object(_ text: String) throws -> [String: Any] {
        guard let o = try JSONSerialization.jsonObject(with: text.utf8Data, options: [.fragmentsAllowed]) as? [String: Any] else {
            throw E2EError.invalidFormat("expected a JSON object")
        }
        return o
    }

    static func array(_ text: String) throws -> [Any] {
        guard let a = try JSONSerialization.jsonObject(with: text.utf8Data) as? [Any] else { throw E2EError.invalidFormat("expected a JSON array") }
        return a
    }
}

extension Dictionary where Key == String, Value == Any {
    func str(_ k: String) throws -> String {
        guard let v = self[k] as? String else { throw E2EError.invalidFormat("missing \(k)") }
        return v
    }
    func optStr(_ k: String) -> String? { self[k] as? String }
    func int(_ k: String) throws -> Int {
        guard let n = optInt(k) else { throw E2EError.invalidFormat("missing \(k)") }
        return n
    }
    func optInt(_ k: String) -> Int? { anyInt(self[k]) }
    func obj(_ k: String) throws -> [String: Any] {
        guard let v = self[k] as? [String: Any] else { throw E2EError.invalidFormat("missing \(k)") }
        return v
    }
    func arr(_ k: String) throws -> [Any] {
        guard let v = self[k] as? [Any] else { throw E2EError.invalidFormat("missing \(k)") }
        return v
    }
}
