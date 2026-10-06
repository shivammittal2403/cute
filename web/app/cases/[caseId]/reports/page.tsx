export default function CaseReportsPage({ params }: { params: { caseId: string } }) {
  return <main>Case {params.caseId} — reports</main>;
}
