import { get, post, put, del } from './client'
import type { View, ViewCreate } from '../types'

export function listViews(): Promise<View[]> {
  return get('/views')
}

export function getView(id: number): Promise<View> {
  return get(`/views/${id}`)
}

export function createView(data: ViewCreate): Promise<{ id: number }> {
  return post('/views', data)
}

export function updateView(id: number, data: ViewCreate): Promise<{ message: string }> {
  return put(`/views/${id}`, data)
}

export function deleteView(id: number): Promise<{ message: string }> {
  return del(`/views/${id}`)
}

export function attachProvider(viewId: number, providerId: number): Promise<{ message: string }> {
  return post(`/views/${viewId}/providers/${providerId}`)
}

export function detachProvider(viewId: number, providerId: number): Promise<{ message: string }> {
  return del(`/views/${viewId}/providers/${providerId}`)
}
