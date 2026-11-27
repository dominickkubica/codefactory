import { Injectable } from "@nestjs/common";
import { execSync } from "child_process";
import * as fs from "fs";

@Injectable()
export class FilesService {
  remove(name: string) {
    fs.unlinkSync(`/srv/uploads/${name}`);   // BAD via the controller
  }

  describe(name: string) {
    return { name, size: 0 };
  }
}

@Injectable()
export class ArchiveService {
  pack(label: string) {
    return execSync("tar czf /tmp/a.tgz /srv/uploads").toString() + label;
  }
}
