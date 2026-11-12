import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { binDir, candidate, env, host, options, root, run, scratchDir } from "./context.mjs";

/** Builds simple-ca-trust for goos/goarch to out, and reports whether it could. */
export function buildTrust(goos, goarch, out, version = "") {
  mkdirSync(dirname(out), { recursive: true });
  if (goos === "linux") {
    const flags = version ? ["-trimpath", "-ldflags", `-X main.buildVersion=${version}`] :
      candidate ? ["-ldflags", `-X main.buildVersion=${candidate}`] : [];
    run("go", ["build", ...flags, "-o", out, "./cmd/simple-ca-trust"], { env: { ...env, GOOS: goos, GOARCH: goarch } });
    return true;
  }
  if (goos === "darwin" && host === "darwin") {
    const macos = join(root, "trust", "macos");
    const arch = ["--arch", { amd64: "x86_64", arm64: "arm64" }[goarch] ?? goarch];
    // Version.swift holds the version during the build.
    const swiftVersion = join(macos, "Sources", "simple-ca-trust", "Version.swift");
    const original = readFileSync(swiftVersion, "utf8");
    if (version) {
      writeFileSync(swiftVersion, "/// The version simple-ca-trust prints; a release build replaces this file.\n" +
        `let version = "${version}"\n`);
    }
    try {
      run("swift", ["build", "-c", "release", "--package-path", macos, ...arch]);
      const bin = run("swift", ["build", "-c", "release", "--package-path", macos, ...arch, "--show-bin-path"],
        { capture: true }).trim();
      copyFileSync(join(bin, "simple-ca-trust"), out);
    } finally {
      writeFileSync(swiftVersion, original);
    }
    return true;
  }
  if (goos === "windows") {
    const project = join(root, "trust", "windows", "simple-ca-trust.csproj");
    writeFileSync(project, `<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <AssemblyName>simple-ca-trust</AssemblyName>
    <RootNamespace>SimpleCaTrust</RootNamespace>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <PublishSingleFile>true</PublishSingleFile>
    <SelfContained>${options.selfContained}</SelfContained>
    <InvariantGlobalization>true</InvariantGlobalization>
    <InformationalVersion Condition="'$(InformationalVersion)' == ''">dev</InformationalVersion>
    <IncludeSourceRevisionInInformationalVersion>false</IncludeSourceRevisionInInformationalVersion>
  </PropertyGroup>

</Project>
`);
    const publish = scratchDir(`trust-windows-${goarch}`);
    try {
      run("dotnet", ["publish", project, "-c", "Release",
        "-r", `win-${{ amd64: "x64", arm64: "arm64" }[goarch] ?? goarch}`, "-o", publish],
        { env: version ? { ...process.env, InformationalVersion: version } : process.env });
      copyFileSync(join(publish, "simple-ca-trust.exe"), out);
    } finally {
      rmSync(publish, { recursive: true, force: true });
    }
    return true;
  }
  return false;
}

export async function trust() {
  const { platform } = options;
  const goos = env.GOOS ?? host;
  const goarch = env.GOARCH ?? { x64: "amd64", arm64: "arm64" }[process.arch] ?? process.arch;
  const name = platform === "" ? "simple-ca-trust" : `simple-ca-trust-${goos}-${goarch}`;
  if (!buildTrust(goos, goarch, join(binDir, goos === "windows" ? `${name}.exe` : name))) {
    console.error(goos === "darwin" ? "note: simple-ca-trust for darwin is built on darwin only; skipped" :
      `note: simple-ca-trust has no version for ${goos}; skipped`);
  }
}
