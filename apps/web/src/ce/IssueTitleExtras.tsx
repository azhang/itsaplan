'use client';

import type { IssueWithWatchers } from '@/lib/api/endpoints/issues';
import type { ProjectDetail } from '@/lib/api/endpoints/projects';

// Under an issue's title, after the repository issue it is synced with, in the issue panel and
// on its page. A self-hosted instance adds none; a build draws each line with IssueSourceLink,
// as the core's is.
export default function IssueTitleExtras(_props: {
  project: ProjectDetail;
  issue: IssueWithWatchers;
}) {
  return null;
}
