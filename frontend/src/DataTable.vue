<script setup lang="ts">
import { computed, ref, watch, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from './api'
const props=withDefaults(defineProps<{endpoint:string,columns:{key:string,label:string}[],refresh?:number,filterStatus?:boolean,statusOptions?:string[],queryKey?:string}>(),{refresh:0,queryKey:'table'})
const route=useRoute(),router=useRouter()
const items=ref<Record<string,any>[]>([]),total=ref(0),pages=ref(0),loading=ref(true),error=ref('')
const key=(x:string)=>`${props.queryKey}_${x}`
const search=ref(String(route.query[key('search')]||'')),page=ref(Number(route.query[key('page')])||1)
const size=ref(Number(route.query[key('size')])||25),status=ref(String(route.query[key('status')]||''))
const order=ref(String(route.query[key('order')]||'desc')),sort=ref(String(route.query[key('sort')]||'created_at'))
const sortable=computed(()=>[...new Set(['created_at',...props.columns.map(c=>c.key).filter(k=>['name','updated_at','last_run_at','ip','port','url','username','label','kind','status','change','product','version','attempted_at','captured_at'].includes(k))])])
let version=0, timer:ReturnType<typeof setInterval>|undefined
async function load(quiet=false){const current=++version;if(!quiet)loading.value=true;error.value='';try{
  const query=new URLSearchParams({page:String(page.value),page_size:String(size.value),search:search.value,sort_by:sort.value,sort_order:order.value})
  if(status.value)query.set('status',status.value)
  const data=await api(props.endpoint+'?'+query)
  if(current!==version)return
  items.value=data.items;total.value=data.total;pages.value=data.total_pages
}catch(e){if(current===version)error.value=(e as Error).message}finally{if(current===version)loading.value=false}}
function remember(){void router.replace({query:{...route.query,[key('page')]:String(page.value),[key('size')]:String(size.value),[key('search')]:search.value,[key('status')]:status.value,[key('sort')]:sort.value,[key('order')]:order.value}})}
function searchChanged(){page.value=1;remember();void load()}
watch(()=>props.endpoint,()=>{page.value=1;void load()},{immediate:true})
watch(()=>props.refresh,()=>{if(timer)clearInterval(timer);if(props.refresh)timer=setInterval(()=>void load(true),props.refresh)},{immediate:true})
onUnmounted(()=>{version++;if(timer)clearInterval(timer)})
defineExpose({load})
function display(value:unknown){if(value===null||value===undefined||value==='')return '—';return typeof value==='object'?JSON.stringify(value):String(value)}
</script>
<template><section class="panel table-panel"><div class="table-toolbar"><label class="search">Search<input v-model="search" placeholder="Search results…" type="search" @keydown.enter.prevent="searchChanged"></label><button type="button" class="subtle" @click="searchChanged">Search</button><label v-if="filterStatus">Status<select v-model="status" @change="searchChanged"><option value="">All statuses</option><option v-for="s in statusOptions || ['never','queued','running','pausing','paused','stopping','stopped','completed','failed']" :key="s">{{s}}</option></select></label><label>Sort by<select v-model="sort" @change="searchChanged"><option v-for="field in sortable" :key="field" :value="field">{{field.replaceAll('_',' ')}}</option></select></label><label>Order<select v-model="order" @change="searchChanged"><option value="desc">Newest first</option><option value="asc">Oldest first</option></select></label><label>Per page<select v-model="size" @change="searchChanged"><option :value="10">10</option><option :value="25">25</option><option :value="100">100</option></select></label><button type="button" class="subtle" @click="load()">Refresh</button></div>
<p v-if="error" class="error" role="alert">{{error}}</p><p v-if="loading" role="status" class="empty">Loading…</p>
<div v-else class="table-wrap"><table><thead><tr><th v-for="c in columns" :key="c.key" scope="col">{{c.label}}</th><th v-if="$slots.actions" scope="col">Actions</th></tr></thead><tbody><tr v-for="row in items" :key="row.id"><td v-for="c in columns" :key="c.key"><slot :name="c.key" :row="row" :value="row[c.key]"><span v-if="['status','last_status','change'].includes(c.key)" class="badge" :data-status="row[c.key]">{{display(row[c.key])}}</span><span v-else>{{display(row[c.key])}}</span></slot></td><td v-if="$slots.actions"><div class="actions"><slot name="actions" :row="row"/></div></td></tr></tbody></table><p v-if="!items.length" class="empty">No results found.</p></div>
<div class="pagination"><span>{{total}} items · Page {{page}} of {{Math.max(1,pages)}}</span><div class="actions"><button type="button" class="subtle" :disabled="page<=1" @click="page--;remember();load()">Previous</button><button type="button" class="subtle" :disabled="page>=pages" @click="page++;remember();load()">Next</button></div></div></section></template>
