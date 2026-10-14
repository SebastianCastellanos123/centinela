// Package follow lee líneas de un log, ya sea completo o "en vivo" (como tail -f).
package follow

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

// MaxLine es el largo máximo de línea que aceptamos. Una línea más larga se recorta:
// así un log malicioso (o corrupto) no puede agotar la memoria.
const MaxLine = 64 << 10

// ForEachLine llama a fn por cada línea de r. Las líneas demasiado largas se recortan
// en lugar de abortar la lectura (bufio.Scanner se detendría con ErrTooLong).
func ForEachLine(r io.Reader, fn func(string)) error {
	br := bufio.NewReaderSize(r, MaxLine)
	var sb strings.Builder
	for {
		chunk, err := br.ReadSlice('\n')
		if sb.Len() < MaxLine {
			sb.Write(chunk)
		}
		switch {
		case err == nil: // línea completa
			fn(strings.TrimRight(sb.String(), "\r\n"))
			sb.Reset()
		case errors.Is(err, bufio.ErrBufferFull): // línea larguísima: seguir leyendo hasta su final
			continue
		case errors.Is(err, io.EOF):
			if sb.Len() > 0 {
				fn(strings.TrimRight(sb.String(), "\r\n"))
			}
			return nil
		default:
			return err
		}
	}
}

// Lines sigue el archivo y envía cada línea NUEVA a out hasta que ctx se cancele.
// Si fromStart es false, empieza al final del archivo (solo lo que llegue después).
// Detecta rotación de logs (logrotate renombra el archivo y crea uno nuevo) y truncado.
func Lines(ctx context.Context, path string, fromStart bool, poll time.Duration, out chan<- string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	var offset int64
	if !fromStart {
		if offset, err = f.Seek(0, io.SeekEnd); err != nil {
			return err
		}
	}

	br := bufio.NewReaderSize(f, MaxLine)
	var partial strings.Builder // una línea a medio escribir cuando llegamos al EOF

	send := func(line string) bool {
		select {
		case out <- line:
			return true
		case <-ctx.Done():
			return false
		}
	}

	for {
		chunk, err := br.ReadSlice('\n')
		offset += int64(len(chunk))
		if partial.Len() < MaxLine {
			partial.Write(chunk)
		}
		switch {
		case err == nil:
			if !send(strings.TrimRight(partial.String(), "\r\n")) {
				return nil
			}
			partial.Reset()
			continue
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case !errors.Is(err, io.EOF):
			return err
		}

		// EOF: esperar y ver si el archivo rotó o se truncó.
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(poll):
		}
		cur, serr := os.Stat(path)
		if serr != nil {
			continue // en plena rotación el archivo puede no existir un instante
		}
		if !os.SameFile(info, cur) { // rotación: abrir el archivo nuevo desde el inicio
			nf, oerr := os.Open(path)
			if oerr != nil {
				continue
			}
			f.Close()
			f, info, offset = nf, cur, 0
			br = bufio.NewReaderSize(f, MaxLine)
			partial.Reset()
		} else if cur.Size() < offset { // truncado
			f.Seek(0, io.SeekStart)
			offset = 0
			br.Reset(f)
			partial.Reset()
		}
	}
}
