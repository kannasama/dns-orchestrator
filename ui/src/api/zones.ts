import { get, post, put, del } from './client'
import type { Zone, ZoneCreate } from '../types'

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
  data: { name: string; deployment_retention?: number | null },
): Promise<{ message: string }> {
  return put(`/zones/${id}`, data)
}

export function deleteZone(id: number): Promise<{ message: string }> {
  return del(`/zones/${id}`)
}
