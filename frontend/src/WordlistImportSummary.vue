<script setup lang="ts">
defineProps<{report:{skipped_invalid:number,skipped_comments:number,duplicates:number,examples:string[]}}>()
</script>
<template>
  <section v-if="report.skipped_invalid || report.skipped_comments || report.duplicates" class="panel" aria-label="Wordlist import summary">
    <h2>Wordlist import summary</h2>
    <p>{{report.skipped_invalid}} invalid lines skipped · {{report.skipped_comments}} comments ignored · {{report.duplicates}} duplicates removed</p>
    <p class="muted">Only valid subdomain names were saved for this scan.</p>
    <ul v-if="report.examples.length"><li v-for="example in report.examples" :key="example" class="mono">{{example}}</li></ul>
  </section>
</template>
