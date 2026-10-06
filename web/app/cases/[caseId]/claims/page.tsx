export default function CaseClaimsPage({ params }: { params: { caseId: string } }) {
  return <main>Case {params.caseId} — claims</main>;
}
