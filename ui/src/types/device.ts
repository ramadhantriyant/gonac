export interface Device {
  id: string
  mac_address: string
  ip_address: string
  hostname: string | null
  first_seen: string
  last_seen: string
  is_known: boolean
}
