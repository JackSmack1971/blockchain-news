import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    environmentMatchGlobs: [['server/**', 'node']],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
    },
  },
});
