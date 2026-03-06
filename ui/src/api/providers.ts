import { get, post, put, del } from './client'
import type { Provider, ProviderCreate, ProviderUpdate } from '../types'

export function listProviders(): Promise<Provider[]> {
  return get('/providers')
}

export function getProvider(id: number): Promise<Provider> {
  return get(`/providers/${id}`)
}

export function createProvider(data: ProviderCreate): Promise<{ id: number }> {
  return post('/providers', data)
}

export function updateProvider(id: number, data: ProviderUpdate): Promise<{ message: string }> {
  return put(`/providers/${id}`, data)
}

export function deleteProvider(id: number): Promise<{ message: string }> {
  return del(`/providers/${id}`)
}
