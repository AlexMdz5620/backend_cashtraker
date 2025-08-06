const { createDefaultPreset } = require("ts-jest");

const tsJestTransformCfg = createDefaultPreset().transform;

/** @type {import("jest").Config} */
module.exports = {
  testEnvironment: "node",
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        useESM: false, // si usas ESM, cámbialo a true
        tsconfig: "./tsconfig.json"
      }
    ],
  },
};
