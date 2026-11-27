import { Controller, Post, Body, Param, ParseIntPipe, Get } from "@nestjs/common";
@Controller("users")
export class UsersController {
  constructor(private readonly ds: DataSource) {}
  @Post(":id")
  async update(@Param("id", ParseIntPipe) id: number, @Body() dto: UpdateDto) {
    await this.ds.query(`UPDATE users SET name = '${dto.name}' WHERE id = ${id}`);   // BAD sql (dto)
  }
  @Get()
  async list(@Param("id", ParseIntPipe) id: number) {
    await this.ds.query(`SELECT * FROM users WHERE id = ${id}`);   // ok
  }
}
