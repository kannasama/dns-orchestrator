import { get, post, put, del } from './client'
import type { Zone, ZoneCreate, ZoneSyncResult } from '../types'

export function listZones(viewId?: number): Promise<Zone[]> {
  const query = viewId !== undefined ? `?view_id=${viewId}` : ''
  return get(`/zones${query}`)
}

export function getZone(id: number): Promise<Zone> {
  return get(`/zones/${id}`)
}

export function createZone(data: ZoneCreate): Promise<{ id: number }> {
  return post('/zones', data)
}

export function updateZone(
  id: number,
  data: {
    name: string
    view_id?: number | null
    deployment_retention?: number | null
    manage_soa?: boolean
    manage_ns?: boolean
    git_repo_id?: number | null
    git_branch?: string | null
  },
): Promise<{ message: string }> {
  return put(`/zones/${id}`, data)
}

export function deleteZone(id: number): Promise<{ message: string }> {
  return del(`/zones/${id}`)
}

export function syncCheckZone(id: number): Promise<ZoneSyncResult> {
  return post(`/zones/${id}/sync-check`)
}

export interface SyncCheckAllResult {
  results: ZoneSyncResult[]
  server_time: number
}

export async function syncCheckAll(): Promise<SyncCheckAllResult> {
  return post('/zones/sync-check')
}
