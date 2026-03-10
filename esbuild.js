const esbuild = require("esbuild");

const isWatch = process.argv.includes("--watch");

const ctxPromise = esbuild.context({
  entryPoints: ["src/extension.ts"],
  bundle: true,
  outfile: "dist/extension.js",
  external: ["vscode"],
  platform: "node",
  format: "cjs",
  target: "node18",
  sourcemap: true,
  logLevel: "info"
});

ctxPromise
  .then((ctx) => {
    if (isWatch) {
      return ctx.watch();
    }
    return ctx.rebuild().finally(() => ctx.dispose());
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
