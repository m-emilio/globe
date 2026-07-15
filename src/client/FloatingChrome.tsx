import React, {
  useCallback,
  useEffect,
  useRef,
  useState,
  type CSSProperties,
  type HTMLAttributes,
  type PointerEvent as ReactPointerEvent,
  type ReactNode,
} from "react";

type FloatingChromeProps = HTMLAttributes<HTMLDivElement> & {
  children: ReactNode;
  /** Extra class names merged with floating-chrome */
  className?: string;
};

type DragState = {
  pointerId: number;
  startX: number;
  startY: number;
  origLeft: number;
  origTop: number;
};

type ResizeState = {
  pointerId: number;
  startX: number;
  startY: number;
  origWidth: number;
  origHeight: number;
};

/** Only start a drag from these chrome surfaces — never from scrollable body content. */
const DRAG_HANDLE_SELECTOR = [
  ".un-panel-header",
  ".weather-panel-header",
  ".activity-header",
  ".menu-section-title",
  ".modal-content > h2",
  ".floating-chrome-drag",
].join(", ");

const INTERACTIVE_SELECTOR =
  "button, a, input, select, textarea, label, option, summary, [role='button'], [role='menuitem'], [contenteditable='true'], .floating-chrome-resize";

/**
 * Wraps a popup/panel so users can drag it (click-hold on the header)
 * and resize it from the bottom-right grip. Unmount (close) fully resets layout.
 */
export function FloatingChrome({
  children,
  className = "",
  style,
  onPointerDown,
  ...rest
}: FloatingChromeProps) {
  const rootRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<DragState | null>(null);
  const resizeRef = useRef<ResizeState | null>(null);

  // null = use original CSS placement; set after first drag
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null);
  // null = use original CSS size; set only after an explicit user resize
  const [size, setSize] = useState<{ width: number; height: number } | null>(
    null,
  );

  const isMinimized = className.includes("un-panel-minimized");

  const onDragPointerDown = useCallback(
    (e: ReactPointerEvent<HTMLDivElement>) => {
      onPointerDown?.(e);
      if (e.defaultPrevented) return;
      if (e.button !== 0) return;

      const target = e.target;
      if (!(target instanceof Element)) return;

      // Never steal events from buttons/links/inputs
      if (target.closest(INTERACTIVE_SELECTOR)) return;

      // Only drag from the header / designated handle — body stays free for scroll
      if (!target.closest(DRAG_HANDLE_SELECTOR)) return;

      const el = rootRef.current;
      if (!el) return;

      const rect = el.getBoundingClientRect();
      dragRef.current = {
        pointerId: e.pointerId,
        startX: e.clientX,
        startY: e.clientY,
        origLeft: rect.left,
        origTop: rect.top,
      };

      // Anchor with left/top only — do not lock height/width (avoids minimize + scroll glitches)
      setPos({ left: rect.left, top: rect.top });

      try {
        el.setPointerCapture(e.pointerId);
      } catch {
        // ignore
      }
      // Keep default touch scrolling behavior elsewhere; only prevent text selection while dragging
      e.preventDefault();
    },
    [onPointerDown],
  );

  const onResizePointerDown = useCallback(
    (e: ReactPointerEvent<HTMLDivElement>) => {
      e.stopPropagation();
      e.preventDefault();
      if (e.button !== 0) return;

      const el = rootRef.current;
      if (!el) return;

      const rect = el.getBoundingClientRect();
      resizeRef.current = {
        pointerId: e.pointerId,
        startX: e.clientX,
        startY: e.clientY,
        origWidth: rect.width,
        origHeight: rect.height,
      };

      // Keep position stable while resizing (switch to left/top anchors)
      if (!pos) {
        setPos({ left: rect.left, top: rect.top });
      }
      setSize({ width: rect.width, height: rect.height });

      try {
        e.currentTarget.setPointerCapture(e.pointerId);
      } catch {
        // ignore
      }
    },
    [pos],
  );

  useEffect(() => {
    const onMove = (e: PointerEvent) => {
      const el = rootRef.current;

      if (dragRef.current && e.pointerId === dragRef.current.pointerId) {
        const { startX, startY, origLeft, origTop } = dragRef.current;
        const dx = e.clientX - startX;
        const dy = e.clientY - startY;
        const width = el?.offsetWidth ?? 200;
        const height = el?.offsetHeight ?? 120;
        const maxLeft = Math.max(0, window.innerWidth - Math.min(width, 80));
        const maxTop = Math.max(0, window.innerHeight - Math.min(height, 48));
        setPos({
          left: Math.min(Math.max(0, origLeft + dx), maxLeft),
          top: Math.min(Math.max(0, origTop + dy), maxTop),
        });
        return;
      }

      if (resizeRef.current && e.pointerId === resizeRef.current.pointerId) {
        const { startX, startY, origWidth, origHeight } = resizeRef.current;
        const minW = 220;
        const minH = 120;
        const maxW = window.innerWidth - 8;
        const maxH = window.innerHeight - 8;
        const nextW = Math.min(
          maxW,
          Math.max(minW, origWidth + (e.clientX - startX)),
        );
        const nextH = Math.min(
          maxH,
          Math.max(minH, origHeight + (e.clientY - startY)),
        );
        setSize({ width: nextW, height: nextH });
      }
    };

    const onUp = (e: PointerEvent) => {
      if (dragRef.current && e.pointerId === dragRef.current.pointerId) {
        dragRef.current = null;
      }
      if (resizeRef.current && e.pointerId === resizeRef.current.pointerId) {
        resizeRef.current = null;
      }
    };

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    window.addEventListener("pointercancel", onUp);
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", onUp);
    };
  }, []);

  const mergedStyle: CSSProperties = {
    ...style,
    ...(pos
      ? {
          position: "fixed",
          left: pos.left,
          top: pos.top,
          right: "auto",
          bottom: "auto",
          margin: 0,
        }
      : null),
    ...(size
      ? {
          width: size.width,
          maxWidth: "none",
          // While minimized, never force a tall locked height
          ...(isMinimized
            ? { height: "auto", maxHeight: "none" }
            : { height: size.height, maxHeight: "none" }),
        }
      : null),
  };

  return (
    <div
      ref={rootRef}
      className={["floating-chrome", className].filter(Boolean).join(" ")}
      {...rest}
      style={mergedStyle}
      onPointerDown={onDragPointerDown}
    >
      {children}
      {!isMinimized && (
        <div
          className="floating-chrome-resize"
          onPointerDown={onResizePointerDown}
          aria-hidden="true"
          title="Drag to resize"
        />
      )}
    </div>
  );
}
