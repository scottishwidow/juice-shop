import { mkdtempSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

export function createTaskflowDataDir (prefix: string): string {
  const dataDir = mkdtempSync(path.join(tmpdir(), prefix))
  mkdirSync(path.join(dataDir, 'logs'), { recursive: true })
  return dataDir
}
