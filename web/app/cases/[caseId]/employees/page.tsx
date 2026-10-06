export default function CaseEmployeesPage({ params }: { params: { caseId: string } }) {
  return <main>Case {params.caseId} — employees</main>;
}
