import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { binDir, buildDir, candidate, env, options, root, run } from "./context.mjs";

const goBuild = (output, pkg) => {
  mkdirSync(binDir, { recursive: true });
  run("go", ["build", ...(candidate ? ["-ldflags", `-X main.buildVersion=${candidate}`] : []), "-o",
    join(binDir, output), pkg], { env });
};

export async function build() {
  const { platform } = options;
  // The suffix of the executables: -<goos>-<goarch> for a platform named, and .exe on Windows.
  const nameSuffix = platform === "" ? run("go", ["env", "GOEXE"], { env, capture: true }).trim() :
    `-${env.GOOS}-${env.GOARCH}${env.GOOS === "windows" ? ".exe" : ""}`;
  goBuild(`simple-ca${nameSuffix}`, ".");
  goBuild(`request-cert${nameSuffix}`, "./cmd/request-cert");
  goBuild(`token-setup${nameSuffix}`, "./cmd/token-setup");
  goBuild(`request-token${nameSuffix}`, "./cmd/request-token");
  goBuild(`simple-ca-wif${nameSuffix}`, "./cmd/simple-ca-wif");
  goBuild(`simple-ca-lite${nameSuffix}`, "./cmd/simple-ca-lite");
  if (platform !== "" ? env.GOOS === "linux" : process.platform === "linux") {
    goBuild(`simple-ca-trust${nameSuffix}`, "./cmd/simple-ca-trust");
  }
}

export async function test() {
  run("go", ["test", "./..."], { env });
}

export async function check() {
  const unformatted = run("gofmt", ["-l", "."], { capture: true }).trim();
  if (unformatted !== "") {
    console.error(`these files are not gofmt clean:\n${unformatted}`);
    process.exit(1);
  }
  run("go", ["vet", "./..."], { env });
  run("go", ["test", "./..."], { env });
}

export async function clean() {
  rmSync(binDir, { recursive: true, force: true });
  rmSync(buildDir, { recursive: true, force: true });
  rmSync(`${root}/dist`, { recursive: true, force: true });
  rmSync(`${root}/apt`, { recursive: true, force: true });
  for (const dir of ["trust/macos/.build", "trust/windows/bin", "trust/windows/obj", "trust/windows/simple-ca-trust.csproj"]) {
    rmSync(join(root, dir), { recursive: true, force: true });
  }
}
