import { ChevronLeft, ChevronRight } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

type PaginationProps = {
  currentPage: number;
  totalPages: number;
  totalItems: number;
  onPageChange: (page: number) => void;
};

export function usePagination<T>(items: T[], pageSize: number) {
  const [currentPage, setCurrentPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(items.length / pageSize));

  useEffect(() => {
    setCurrentPage((page) => Math.min(page, totalPages));
  }, [totalPages]);

  const pageItems = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return items.slice(start, start + pageSize);
  }, [currentPage, items, pageSize]);

  return { currentPage, pageItems, setCurrentPage, totalPages };
}

export function Pagination({
  currentPage,
  totalPages,
  totalItems,
  onPageChange,
}: PaginationProps) {
  if (totalItems === 0) return null;

  return (
    <nav className="pagination" aria-label="Paginacion de certificados">
      <span>{totalItems} certificados</span>
      <div className="paginationControls">
        <button
          type="button"
          title="Pagina anterior"
          aria-label="Pagina anterior"
          disabled={currentPage === 1}
          onClick={() => onPageChange(currentPage - 1)}
        >
          <ChevronLeft size={17} />
        </button>
        <strong>Pagina {currentPage} de {totalPages}</strong>
        <button
          type="button"
          title="Pagina siguiente"
          aria-label="Pagina siguiente"
          disabled={currentPage === totalPages}
          onClick={() => onPageChange(currentPage + 1)}
        >
          <ChevronRight size={17} />
        </button>
      </div>
    </nav>
  );
}
