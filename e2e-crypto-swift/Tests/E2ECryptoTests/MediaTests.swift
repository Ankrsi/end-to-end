import XCTest
@testable import E2ECrypto

final class MediaTests: XCTestCase {
    /// Writes the locked bytes to a temp file and returns its file:// url.
    private func saved(_ data: Data, as name: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        try data.write(to: url)
        return url
    }

    func testRoundTripTypeAndTamper() async throws {
        let f = try Media.encryptFile(Data("hello photo".utf8))
        let url = try saved(f.data, as: "photo-\(UUID().uuidString).JPEG")
        let out = try await Media.decryptFile(key: Base64.encode(f.key), url: url)
        XCTAssertEqual(String(decoding: out.data, as: UTF8.self), "hello photo")
        XCTAssertEqual(out.type, "jpeg")

        var bad = f.data
        bad[30] ^= 1
        let badUrl = try saved(bad, as: "bad-\(UUID().uuidString).png")
        do {
            _ = try await Media.decryptFile(key: Base64.encode(f.key), url: badUrl)
            XCTFail("tampered file was accepted")
        } catch {}
    }

    func testDecryptsFileLockedByJS() async throws {
        let data = try Base64.decode("nTdjzZ3jGmJsIwuVMdu2MNI4q+vnsbQEd30lGKENj9JGHoa6nkSXbzK0rxxdtJIV9hbZMus=")
        let url = try saved(data, as: "js-\(UUID().uuidString).mp4")
        let out = try await Media.decryptFile(key: "MPoOv4q5P9T2Wkr9su3y64NegtUg8Ff7b84jgnsFCV0=", url: url)
        XCTAssertEqual(String(decoding: out.data, as: UTF8.self), "hello from js")
        XCTAssertEqual(out.type, "mp4")
    }
}
