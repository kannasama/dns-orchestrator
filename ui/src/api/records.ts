import { get, post, put, del } from './client'
import type { DnsRecord, RecordCreate } from '../types'

export function listRecords(zoneId: number): Promise<DnsRecord[]> {
  return get(`/zones/${zoneId}/records`)
}

export function getRecord(zoneId: number, recordId: number): Promise<DnsRecord> {
  return get(`/zones/${zoneId}/records/${recordId}`)
}

export function createRecord(zoneId: number, data: RecordCreate): Promise<{ id: number }> {
  return post(`/zones/${zoneId}/records`, data)
}

export function updateRecord(
  zoneId: number,
  recordId: number,
  data: RecordCreate,
): Promise<{ message: string }> {
  return put(`/zones/${zoneId}/records/${recordId}`, data)
}

export function deleteRecord(zoneId: number, recordId: number): Promise<{ message: string }> {
  return del(`/zones/${zoneId}/records/${recordId}`)
}
