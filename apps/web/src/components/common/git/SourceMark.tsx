import { useSourceMark } from '@/hooks/useSourceMark';

// The mark of a source without a tooltip, for a place that has one of its own or is not
// pointed at.
export default function SourceMark({ source, className }: { source: string; className?: string }) {
  return useSourceMark(source, className).mark;
}
