import { get, post, put, del } from './client'
import type { Variable, VariableCreate } from '../types'

export function listVariables(scope?: string, zoneId?: number): Promise<Variable[]> {
  const params = new URLSearchParams()
  if (scope) params.set('scope', scope)
  if (zoneId !== undefined) params.set('zone_id', String(zoneId))
  const query = params.toString() ? `?${params.toString()}` : ''
  return get(`/variables${query}`)
}

export function getVariable(id: number): Promise<Variable> {
  return get(`/variables/${id}`)
}

export function createVariable(data: VariableCreate): Promise<{ id: number }> {
  return post('/variables', data)
}

export function updateVariable(id: number, value: string): Promise<{ message: string }> {
  return put(`/variables/${id}`, { value })
}

export function deleteVariable(id: number): Promise<{ message: string }> {
  return del(`/variables/${id}`)
}
