import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export interface CheckResult {
  name: string;
  status: 'PASS' | 'FAIL';
  output?: string;
  error?: string;
}

export async function runSecurityAudit(): Promise<CheckResult[]> {
  const checks = [
    { name: 'npm audit', command: 'npm audit --audit-level high' },
    { name: 'dependency check', command: 'npx audit-ci --high' },
    { name: 'security tests', command: 'npm run test:security' },
  ];

  const results: CheckResult[] = [];
  for (const check of checks) {
    try {
      const { stdout } = await execAsync(check.command);
      results.push({ name: check.name, status: 'PASS', output: stdout });
    } catch (error) {
      const err = error as Error;
      results.push({ name: check.name, status: 'FAIL', error: err.message });
    }
  }

  return results;
}

if (require.main === module) {
  runSecurityAudit().then(r => console.log(JSON.stringify(r, null, 2)));
}
