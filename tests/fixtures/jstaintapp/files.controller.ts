import { Body, Controller, Delete, Param, Post } from "@nestjs/common";
import { ArchiveService, FilesService } from "./files.service";

@Controller("files")
export class FilesController {
  constructor(
    private readonly files: FilesService,
    private readonly archive: ArchiveService,
  ) {}

  @Delete(":name")
  remove(@Param("name") name: string) {
    return this.files.remove(name);   // a sink in the injected service, found by the field's type
  }

  @Post("pack")
  pack(@Body() body: { label: string }) {
    this.files.describe(body.label);   // ok: no sink behind it
    return this.archive.pack(body.label);   // ok: the label never reaches the command
  }
}
