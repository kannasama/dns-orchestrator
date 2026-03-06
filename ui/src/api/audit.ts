import { get, del, apiRequest } from './client'
import type { AuditEntry, PurgeResult } from '../types'

export interface AuditQuery {
  entity_type?: string
  identity?: string
  from?: string
  to?: string
  limit?: number
}

export function queryAudit(query: AuditQuery = {}): Promise<AuditEntry[]> {
  const params = new URLSearchParams()
  if (query.entity_type) params.set('entity_type', query.entity_type)
  if (query.identity) params.set('identity', query.identity)
  if (query.from) params.set('from', query.from)
  if (query.to) params.set('to', query.to)
  if (query.limit) params.set('limit', String(query.limit))
  const qs = params.toString() ? `?${params.toString()}` : ''
  return get(`/audit${qs}`)
}

export async function exportAudit(from?: string, to?: string): Promise<string> {
  const params = new URLSearchParams()
  if (from) params.set('from', from)
  if (to) params.set('to', to)
  const qs = params.toString() ? `?${params.toString()}` : ''
  return apiRequest<string>(`/audit/export${qs}`)
}

export function purgeAudit(): Promise<PurgeResult> {
  return del('/audit/purge')
}
