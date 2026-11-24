import UIKit

final class FeedViewController: UIViewController {
    var timer: Timer?
    let fileURL = URL(fileURLWithPath: "/tmp/feed.json")

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        let items = try? String(contentsOf: fileURL)
        NotificationCenter.default.addObserver(forName: .feedChanged, object: nil, queue: .main) { _ in
            self.reload()
        }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            self?.tick()
        }
        _ = items
    }

    func title(from dict: [String: Any]) -> String {
        let name = dict["name"] as! String
        guard let subtitle = dict["subtitle"] as? String else { return name }
        return name + subtitle
    }

    func didLogin(_ user: User) {
        print("logged in: \(user.email)")
    }

    func reload() {}
    func tick() {}
}
