import Combine
import UIKit

final class ProfileViewController: UIViewController {
    var bag = Set<AnyCancellable>()
    var onClose: (() -> Void)?
    let model = ProfileModel()

    override func viewDidLoad() {
        super.viewDidLoad()
        let avatar = try? Data(contentsOf: model.avatarURL)
        model.$name.sink { name in
            self.title = name
        }.store(in: &bag)
        model.$email.sink { [weak self] email in
            self?.navigationItem.prompt = email
        }.store(in: &bag)
        onClose = { [unowned self] in self.dismiss(animated: true) }
        print("profile for", model.user.email)
        print("Loaded the profile screen")
        UserDefaults.standard.set(model.user.email, forKey: "lastEmail")
        UserDefaults.standard.set(true, forKey: "seenProfile")
        _ = avatar
    }

    func reload() {
        Task {
            let data = try Data(contentsOf: model.avatarURL)
            _ = data
        }
    }

    func cell(_ view: UIView) -> ProfileCell {
        return view as! ProfileCell
    }

    func decode(_ data: Data) -> Profile {
        let config = try! JSONDecoder().decode(Profile.self, from: data)
        let maybe = try? JSONDecoder().decode(Profile.self, from: data)
        return maybe ?? config
    }
}
