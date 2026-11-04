/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['<rootDir>/tests/**/*.test.ts'],
  setupFilesAfterEnv: ['<rootDir>/tests/support/setup.ts'],
  collectCoverageFrom: ['src/**/*.ts', '!src/server.ts'],
  coverageReporters: ['text-summary', 'lcov'],
};
