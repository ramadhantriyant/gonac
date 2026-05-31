import type { Device } from '@/types/device'

const BASE = '/api'

export async function listDevices(): Promise<Device[]> {
  const res = await fetch(`${BASE}/devices`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export async function markKnownByID(id: string): Promise<Device> {
  const res = await fetch(`${BASE}/devices/id/${id}/known`, { method: 'PUT' })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}
