import { execFileSync } from 'node:child_process'
import { cpSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

export interface GitOptions {
  cwd?: string
  env?: NodeJS.ProcessEnv
}

export type RunGit = (args: string[], options?: GitOptions) => string

export function git (args: string[], options: GitOptions = {}): string {
  return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...options })
}

export function prepareAgentWorkspace (runGit: RunGit = git): string {
  const workspace = mkdtempSync(path.join(tmpdir(), 'security-agent-workspace-'))
  runGit(['checkout-index', '-a', '-f', `--prefix=${workspace}${path.sep}`])
  runGit(['init', '-q'], { cwd: workspace })
  runGit(['add', '-A', '--force'], { cwd: workspace })
  runGit([
    '-c', 'user.name=security-agent',
    '-c', 'user.email=security-agent@localhost',
    '-c', 'commit.gpgsign=false',
    'commit', '-q', '--no-verify', '-m', 'baseline'
  ], { cwd: workspace })
  return workspace
}

export function copyInstalledDependencies (workspace: string, checkout: string = process.cwd()): void {
  cpSync(path.join(checkout, 'node_modules'), path.join(workspace, 'node_modules'), {
    recursive: true,
    verbatimSymlinks: true
  })
}
