import type { RecordCreate } from '../types'

export interface ParseResult {
  records: RecordCreate[]
  warnings: string[]
}

export function parseCsv(text: string): ParseResult {
  const warnings: string[] = []
  const lines = text.trim().split('\n')
  if (lines.length < 2) {
    return { records: [], warnings: ['File must have a header row and at least one data row'] }
  }

  const header = lines[0].toLowerCase().split(',').map((h) => h.trim())
  const nameIdx = header.indexOf('name')
  const typeIdx = header.indexOf('type')
  const valueIdx = header.indexOf('value')
  const ttlIdx = header.indexOf('ttl')
  const priorityIdx = header.indexOf('priority')

  if (nameIdx === -1 || typeIdx === -1 || valueIdx === -1) {
    return { records: [], warnings: ['Header must contain name, type, and value columns'] }
  }

  const records: RecordCreate[] = []
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim()
    if (!line) continue
    const cols = line.split(',').map((c) => c.trim())
    const name = cols[nameIdx] || ''
    const type = cols[typeIdx]?.toUpperCase() || ''
    const value = cols[valueIdx] || ''

    if (!name || !type || !value) {
      warnings.push(`Row ${i + 1}: missing required field(s), skipped`)
      continue
    }

    records.push({
      name,
      type,
      value_template: value,
      ttl: ttlIdx !== -1 && cols[ttlIdx] ? parseInt(cols[ttlIdx], 10) || 300 : 300,
      priority: priorityIdx !== -1 && cols[priorityIdx] ? parseInt(cols[priorityIdx], 10) || 0 : 0,
    })
  }

  return { records, warnings }
}

export function parseJson(text: string): ParseResult {
  const warnings: string[] = []
  try {
    const data = JSON.parse(text)
    if (!Array.isArray(data)) {
      return { records: [], warnings: ['JSON must be an array of record objects'] }
    }

    const records: RecordCreate[] = []
    data.forEach((item: Record<string, unknown>, idx: number) => {
      const name = String(item.name || '')
      const type = String(item.type || '').toUpperCase()
      const value = String(item.value_template || item.value || '')
      if (!name || !type || !value) {
        warnings.push(`Record ${idx}: missing required field(s), skipped`)
        return
      }
      records.push({
        name,
        type,
        value_template: value,
        ttl: typeof item.ttl === 'number' ? item.ttl : 300,
        priority: typeof item.priority === 'number' ? item.priority : 0,
      })
    })
    return { records, warnings }
  } catch {
    return { records: [], warnings: ['Invalid JSON'] }
  }
}

export function parseDnsControl(text: string): ParseResult {
  const warnings: string[] = []
  const records: RecordCreate[] = []

  // Phase 1: Extract var declarations
  const vars: Record<string, string> = {}
  const varRegex = /var\s+(\w+)\s*=\s*"([^"]*)"[;,]?/g
  let match: RegExpExecArray | null
  while ((match = varRegex.exec(text)) !== null) {
    vars[match[1]] = match[2]
  }

  // Phase 2: Extract record macros
  const recordFunctions: Record<string, { hasPriority: boolean }> = {
    A: { hasPriority: false },
    AAAA: { hasPriority: false },
    CNAME: { hasPriority: false },
    MX: { hasPriority: true },
    TXT: { hasPriority: false },
    SRV: { hasPriority: true },
    NS: { hasPriority: false },
    PTR: { hasPriority: false },
  }

  for (const [fn, config] of Object.entries(recordFunctions)) {
    // Match: FN("name", value) or FN("name", priority, "value")
    const pattern = config.hasPriority
      ? new RegExp(`${fn}\\s*\\(\\s*"([^"]*)"\\s*,\\s*(\\d+)\\s*,\\s*("([^"]*)"|([\\w]+))`, 'g')
      : new RegExp(`${fn}\\s*\\(\\s*"([^"]*)"\\s*,\\s*("([^"]*)"|([\\w]+))`, 'g')

    while ((match = pattern.exec(text)) !== null) {
      const name = match[1]
      let value: string
      let priority = 0

      if (config.hasPriority) {
        priority = parseInt(match[2], 10)
        value = match[4] || match[5] || ''
      } else {
        value = match[3] || match[4] || ''
      }

      // Substitute DNSControl variables
      if (!value.startsWith('"') && vars[value]) {
        value = vars[value]
      }

      if (!name || !value) {
        warnings.push(`Could not parse ${fn}() call, skipped`)
        continue
      }

      records.push({
        name,
        type: fn,
        value_template: value,
        ttl: 300,
        priority,
      })
    }
  }

  if (records.length === 0 && text.trim().length > 0) {
    warnings.push('No supported record macros found in input')
  }

  // Warn about unsupported constructs
  if (text.includes('D_EXTEND')) warnings.push('D_EXTEND() is not supported — records skipped')
  if (text.includes('FETCH(')) warnings.push('FETCH() is not supported')
  if (text.includes('require(')) warnings.push('require() imports are not supported')

  return { records, warnings }
}
