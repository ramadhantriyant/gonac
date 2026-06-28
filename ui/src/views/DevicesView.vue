<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { listDevices, markKnownByID } from '@/api/devices'
import type { Device } from '@/types/device'

type Filter = 'all' | 'unknown' | 'known'

const devices = ref<Device[]>([])
const loading = ref(false)
const error = ref<string | null>(null)
const filter = ref<Filter>('all')
const search = ref('')
const marking = ref(new Set<string>())
const lastUpdated = ref<Date | null>(null)

type SortKey = 'status' | 'hostname' | 'ip_address' | 'mac_address' | 'last_seen' | 'first_seen'
const sortKey = ref<SortKey>('last_seen')
const sortAsc = ref(false)

function sortBy(key: SortKey) {
  if (sortKey.value === key) {
    sortAsc.value = !sortAsc.value
  } else {
    sortKey.value = key
    sortAsc.value = true
  }
}

const counts = computed(() => ({
  all: devices.value.length,
  unknown: devices.value.filter((d) => !d.is_known).length,
  known: devices.value.filter((d) => d.is_known).length,
}))

const filtered = computed(() => {
  let list = devices.value
  if (filter.value === 'unknown') list = list.filter((d) => !d.is_known)
  if (filter.value === 'known') list = list.filter((d) => d.is_known)
  const q = search.value.trim().toLowerCase()
  if (q) {
    list = list.filter(
      (d) =>
        d.mac_address.toLowerCase().includes(q) ||
        d.ip_address.includes(q) ||
        (d.hostname ?? '').toLowerCase().includes(q),
    )
  }

  const key = sortKey.value
  const dir = sortAsc.value ? 1 : -1
  return [...list].sort((a, b) => {
    let av: string | number
    let bv: string | number
    switch (key) {
      case 'status':
        av = a.is_known ? 1 : 0
        bv = b.is_known ? 1 : 0
        break
      case 'hostname':
        av = (a.hostname ?? '').toLowerCase()
        bv = (b.hostname ?? '').toLowerCase()
        break
      case 'ip_address':
        av = ipToNumber(a.ip_address)
        bv = ipToNumber(b.ip_address)
        break
      case 'mac_address':
        av = a.mac_address.toLowerCase()
        bv = b.mac_address.toLowerCase()
        break
      case 'last_seen':
        av = new Date(a.last_seen).getTime()
        bv = new Date(b.last_seen).getTime()
        break
      case 'first_seen':
        av = new Date(a.first_seen).getTime()
        bv = new Date(b.first_seen).getTime()
        break
    }
    if (av < bv) return -1 * dir
    if (av > bv) return 1 * dir
    return 0
  })
})

function ipToNumber(ip: string): number {
  return ip.split('.').reduce((acc, part) => acc * 256 + (parseInt(part, 10) || 0), 0)
}

function sortArrow(key: SortKey): string {
  if (sortKey.value !== key) return ''
  return sortAsc.value ? ' ▲' : ' ▼'
}

async function load() {
  loading.value = true
  error.value = null
  try {
    devices.value = await listDevices()
    lastUpdated.value = new Date()
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load devices'
  } finally {
    loading.value = false
  }
}

async function trust(device: Device) {
  marking.value.add(device.id)
  try {
    await markKnownByID(device.id)
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to mark device as known'
  } finally {
    marking.value.delete(device.id)
  }
}

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString()
}

let timer: ReturnType<typeof setInterval>

onMounted(() => {
  load()
  timer = setInterval(load, 30_000)
})

onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="page">
    <header class="page-header">
      <div class="header-left">
        <h1 class="logo">gonac</h1>
        <span class="subtitle">Network Access Control</span>
      </div>
      <div class="header-right">
        <span v-if="lastUpdated" class="last-updated">
          Updated {{ relativeTime(lastUpdated.toISOString()) }}
        </span>
        <button class="btn-refresh" :disabled="loading" @click="load">
          <span :class="{ spinning: loading }">↻</span>
          Refresh
        </button>
      </div>
    </header>

    <main class="content">
      <div class="stats">
        <div class="stat">
          <span class="stat-value">{{ counts.all }}</span>
          <span class="stat-label">Total</span>
        </div>
        <div class="stat stat--warn">
          <span class="stat-value">{{ counts.unknown }}</span>
          <span class="stat-label">Unknown</span>
        </div>
        <div class="stat stat--ok">
          <span class="stat-value">{{ counts.known }}</span>
          <span class="stat-label">Known</span>
        </div>
      </div>

      <div class="toolbar">
        <div class="filters">
          <button
            v-for="f in (['all', 'unknown', 'known'] as Filter[])"
            :key="f"
            class="filter-btn"
            :class="{ active: filter === f }"
            @click="filter = f"
          >
            {{ f.charAt(0).toUpperCase() + f.slice(1) }}
            <span class="filter-count">{{ counts[f] }}</span>
          </button>
        </div>
        <input
          v-model="search"
          class="search"
          type="search"
          placeholder="Filter by hostname, IP, or MAC…"
        />
      </div>

      <div v-if="error" class="error">{{ error }}</div>

      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th class="sortable" @click="sortBy('status')">
                Status<span class="sort-arrow">{{ sortArrow('status') }}</span>
              </th>
              <th class="sortable" @click="sortBy('hostname')">
                Hostname<span class="sort-arrow">{{ sortArrow('hostname') }}</span>
              </th>
              <th class="sortable" @click="sortBy('ip_address')">
                IP Address<span class="sort-arrow">{{ sortArrow('ip_address') }}</span>
              </th>
              <th class="sortable" @click="sortBy('mac_address')">
                MAC Address<span class="sort-arrow">{{ sortArrow('mac_address') }}</span>
              </th>
              <th class="sortable" @click="sortBy('last_seen')">
                Last Seen<span class="sort-arrow">{{ sortArrow('last_seen') }}</span>
              </th>
              <th class="sortable" @click="sortBy('first_seen')">
                First Seen<span class="sort-arrow">{{ sortArrow('first_seen') }}</span>
              </th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="loading && devices.length === 0">
              <td colspan="7" class="cell-empty">Loading…</td>
            </tr>
            <tr v-else-if="filtered.length === 0">
              <td colspan="7" class="cell-empty">No devices found</td>
            </tr>
            <tr
              v-for="device in filtered"
              :key="device.id"
              :class="{ 'row--unknown': !device.is_known }"
            >
              <td>
                <span class="badge" :class="device.is_known ? 'badge--known' : 'badge--unknown'">
                  {{ device.is_known ? 'Known' : 'Unknown' }}
                </span>
              </td>
              <td class="cell-hostname">
                {{ device.hostname ?? '—' }}
              </td>
              <td class="cell-mono">{{ device.ip_address }}</td>
              <td class="cell-mono">{{ device.mac_address }}</td>
              <td>
                <span :title="formatTime(device.last_seen)">
                  {{ relativeTime(device.last_seen) }}
                </span>
              </td>
              <td>
                <span :title="formatTime(device.first_seen)">
                  {{ relativeTime(device.first_seen) }}
                </span>
              </td>
              <td>
                <button
                  v-if="!device.is_known"
                  class="btn-trust"
                  :disabled="marking.has(device.id)"
                  @click="trust(device)"
                >
                  {{ marking.has(device.id) ? '…' : 'Mark as Known' }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </main>
  </div>
</template>

<style scoped>
.page {
  min-height: 100vh;
  background: #f1f5f9;
  font-family:
    system-ui,
    -apple-system,
    sans-serif;
  color: #1e293b;
}

.page-header {
  background: #0f172a;
  color: #f8fafc;
  padding: 0 2rem;
  height: 56px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.header-left {
  display: flex;
  align-items: baseline;
  gap: 0.75rem;
}

.logo {
  font-size: 1.125rem;
  font-weight: 700;
  letter-spacing: 0.05em;
  color: #38bdf8;
  margin: 0;
}

.subtitle {
  font-size: 0.8rem;
  color: #94a3b8;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.last-updated {
  font-size: 0.8rem;
  color: #64748b;
}

.btn-refresh {
  display: flex;
  align-items: center;
  gap: 0.375rem;
  background: #1e293b;
  border: 1px solid #334155;
  color: #cbd5e1;
  border-radius: 6px;
  padding: 0.375rem 0.75rem;
  font-size: 0.8rem;
  cursor: pointer;
  transition: background 0.15s;
}

.btn-refresh:hover:not(:disabled) {
  background: #334155;
}

.btn-refresh:disabled {
  opacity: 0.5;
  cursor: default;
}

.spinning {
  display: inline-block;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

.content {
  max-width: 1200px;
  margin: 0 auto;
  padding: 1.5rem 2rem;
}

.stats {
  display: flex;
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.stat {
  background: #fff;
  border: 1px solid #e2e8f0;
  border-radius: 10px;
  padding: 1rem 1.5rem;
  min-width: 100px;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.stat--warn {
  border-color: #fcd34d;
}

.stat--ok {
  border-color: #86efac;
}

.stat-value {
  font-size: 1.75rem;
  font-weight: 700;
  line-height: 1;
}

.stat-label {
  font-size: 0.75rem;
  color: #64748b;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 1rem;
  flex-wrap: wrap;
}

.filters {
  display: flex;
  gap: 0.25rem;
  background: #fff;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 0.25rem;
}

.filter-btn {
  display: flex;
  align-items: center;
  gap: 0.375rem;
  background: transparent;
  border: none;
  border-radius: 6px;
  padding: 0.375rem 0.75rem;
  font-size: 0.85rem;
  cursor: pointer;
  color: #475569;
  transition: background 0.12s;
}

.filter-btn:hover {
  background: #f1f5f9;
}

.filter-btn.active {
  background: #0f172a;
  color: #f8fafc;
}

.filter-count {
  font-size: 0.7rem;
  background: #e2e8f0;
  color: #475569;
  border-radius: 99px;
  padding: 0 0.4rem;
  min-width: 1.25rem;
  text-align: center;
}

.filter-btn.active .filter-count {
  background: #334155;
  color: #cbd5e1;
}

.search {
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 0.5rem 0.875rem;
  font-size: 0.875rem;
  outline: none;
  width: 280px;
  background: #fff;
  color: #1e293b;
}

.search:focus {
  border-color: #38bdf8;
}

.error {
  background: #fef2f2;
  border: 1px solid #fca5a5;
  color: #b91c1c;
  border-radius: 8px;
  padding: 0.75rem 1rem;
  font-size: 0.875rem;
  margin-bottom: 1rem;
}

.table-wrap {
  background: #fff;
  border: 1px solid #e2e8f0;
  border-radius: 10px;
  overflow: hidden;
}

.table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}

.table thead th {
  background: #f8fafc;
  padding: 0.75rem 1rem;
  text-align: left;
  font-weight: 600;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: #64748b;
  border-bottom: 1px solid #e2e8f0;
}

.table thead th.sortable {
  cursor: pointer;
  user-select: none;
}

.table thead th.sortable:hover {
  color: #1e293b;
}

.sort-arrow {
  font-size: 0.65rem;
}

.table tbody tr {
  border-bottom: 1px solid #f1f5f9;
  transition: background 0.1s;
}

.table tbody tr:last-child {
  border-bottom: none;
}

.table tbody tr:hover {
  background: #f8fafc;
}

.table tbody tr.row--unknown {
  background: #fffbeb;
}

.table tbody tr.row--unknown:hover {
  background: #fef9c3;
}

.table td {
  padding: 0.75rem 1rem;
  color: #374151;
}

.cell-empty {
  text-align: center;
  color: #94a3b8;
  padding: 3rem 1rem !important;
}

.cell-hostname {
  font-weight: 500;
  color: #1e293b;
}

.cell-mono {
  font-family: 'SF Mono', 'Consolas', monospace;
  font-size: 0.8rem;
  color: #334155;
}

.badge {
  display: inline-block;
  border-radius: 99px;
  padding: 0.2rem 0.6rem;
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.03em;
}

.badge--known {
  background: #dcfce7;
  color: #15803d;
}

.badge--unknown {
  background: #fef9c3;
  color: #a16207;
}

.btn-trust {
  background: #0f172a;
  color: #f8fafc;
  border: none;
  border-radius: 6px;
  padding: 0.375rem 0.75rem;
  font-size: 0.8rem;
  cursor: pointer;
  white-space: nowrap;
  transition: background 0.15s;
}

.btn-trust:hover:not(:disabled) {
  background: #1e3a5f;
}

.btn-trust:disabled {
  opacity: 0.5;
  cursor: default;
}
</style>
