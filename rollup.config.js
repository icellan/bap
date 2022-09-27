import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import typescript from "@rollup/plugin-typescript";
import json from "@rollup/plugin-json";
import nodePolyfills from 'rollup-plugin-polyfill-node';
import excludeDependenciesFromBundle from "rollup-plugin-exclude-dependencies-from-bundle";
import dts from 'rollup-plugin-dts';
import builtins from 'rollup-plugin-node-builtins';
import pkg from "./package.json";

export default [
  // browser-friendly UMD build
  {
    input: "src/index.ts",
    output: {
      name: "typescriptNpmPackage",
      file: pkg.browser,
      format: "umd",
      sourcemap: true,
    },
    external: ['bsv'],
    plugins: [
      builtins(),
      resolve({
        skip: ['bsv'],
        browser: true,
        preferBuiltins: true,
      }),
      commonjs(),
      json(),
      typescript({tsconfig: "./tsconfig.json", sourceMap: false}),
      nodePolyfills(),
    ],
  },

  // CommonJS (for Node) and ES module (for bundlers) build.
  // (We could have three entries in the configuration array
  // instead of two, but it's quicker to generate multiple
  // builds from a single configuration where possible, using
  // an array for the `output` option, where we can specify
  // `file` and `format` for each target)
  {
    input: "src/index.ts",
    output: [
      {file: pkg.main, format: "cjs", sourcemap: true},
      {file: pkg.module, format: "es", sourcemap: true},
    ],
    plugins: [
      typescript({tsconfig: "./tsconfig.json", sourceMap: false}),
      excludeDependenciesFromBundle({peerDependencies: true}),
    ],
  },

  {
    // path to your declaration files root
    input: './dist/src/index.d.ts',
    output: [
      {file: 'dist/typescript-npm-package.cjs.d.ts', format: 'es'},
      {file: 'dist/typescript-npm-package.esm.d.ts', format: 'es'},
      {file: 'dist/typescript-npm-package.umd.d.ts', format: 'es'}
    ],
    plugins: [dts()],
  },
];
