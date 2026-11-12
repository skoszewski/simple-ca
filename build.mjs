#!/usr/bin/env node

// Builds, tests, checks and packages simple-ca; the actions are the modules of lib/.

import { parseArguments } from "./lib/args.mjs";
import { assets, ensureMarkdownAssets } from "./lib/assets.mjs";
import { apt, setup } from "./lib/builder.mjs";
import { options } from "./lib/context.mjs";
import { deb } from "./lib/deb.mjs";
import { dist } from "./lib/dist.mjs";
import { build, check, clean, test } from "./lib/go.mjs";
import { image } from "./lib/image.mjs";
import { install } from "./lib/install.mjs";
import { sums } from "./lib/sums.mjs";
import { trust } from "./lib/trust.mjs";

const actions = {
  assets, build, trust, docker: image, container: image, deb, dist, install, apt, setup, sums, test, check, clean,
};

parseArguments();
await ensureMarkdownAssets();
await actions[options.action]();
