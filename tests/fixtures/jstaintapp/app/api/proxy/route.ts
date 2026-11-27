import { NextRequest, NextResponse } from "next/server";
export async function GET(request: NextRequest) {
  const u = request.nextUrl.searchParams.get("u");
  const r = await fetch(u!);                   // BAD ssrf
  return NextResponse.redirect(u);             // BAD redirect
}
export async function POST(request: Request, { params }: { params: { id: string } }) {
  const body = await request.json();
  await prisma.$queryRawUnsafe(`SELECT * FROM t WHERE id = ${params.id} AND x = ${body.x}`);  // BAD sql
}
