import { useCallback, useEffect, useRef, useState } from 'react';

const RESET_DELAY_MS = 2000;

function writeTextFallback(text) {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'absolute';
  textarea.style.left = '-9999px';
  document.body.appendChild(textarea);

  const selection = document.getSelection();
  const previouslySelectedRange = selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null;

  textarea.select();
  textarea.setSelectionRange(0, textarea.value.length);

  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch (err) {
    console.error('Copy fallback (execCommand) failed:', err);
  }

  if (previouslySelectedRange) {
    selection.removeAllRanges();
    selection.addRange(previouslySelectedRange);
  }
  document.body.removeChild(textarea);
  return ok;
}

export function useCopyToClipboard() {
  const [copied, setCopied] = useState(false);
  const timerRef = useRef(null);

  useEffect(() => {
    return () => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
      }
    };
  }, []);

  const copy = useCallback(async (text) => {
    const value = String(text ?? '');
    if (!value) return false;

    if (timerRef.current) {
      clearTimeout(timerRef.current);
    }

    let ok = false;
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(value);
        ok = true;
      } catch (err) {
        console.error('navigator.clipboard.writeText failed, trying fallback:', err);
      }
    }

    if (!ok) {
      ok = writeTextFallback(value);
    }

    if (ok) {
      setCopied(true);
      timerRef.current = setTimeout(() => setCopied(false), RESET_DELAY_MS);
    } else {
      console.error('Failed to copy text to clipboard.');
    }

    return ok;
  }, []);

  return [copied, copy];
}