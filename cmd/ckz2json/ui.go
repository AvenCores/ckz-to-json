package main

// Visual style for the built-in interactive UI: banner, headings, colors.

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"ckz2json/internal/prompt"
)

const bannerWidth = 58

// h1 renders a step/section heading on its own line.
func h1(s string) string {
	return "\n" + prompt.Paint(prompt.Bold+";"+prompt.FgCyan, "» "+s)
}

func hint(s string) string { return prompt.Paint(prompt.FgGray, s) }

func ok(s string) string { return prompt.Paint(prompt.FgGreen, s) }

func drawBanner() {
	frame := func(l, r string) {
		fmt.Println(prompt.Paint(prompt.FgCyan, l+strings.Repeat("═", bannerWidth)+r))
	}
	center := func(s, code string) {
		n := utf8.RuneCountInString(s)
		padL := (bannerWidth - n) / 2
		padR := bannerWidth - n - padL
		fmt.Println(prompt.Paint(prompt.FgCyan, "║") + strings.Repeat(" ", padL) +
			prompt.Paint(code, s) + strings.Repeat(" ", padR) +
			prompt.Paint(prompt.FgCyan, "║"))
	}
	frame("╔", "╗")
	center(fmt.Sprintf("c k z 2 j s o n   v%s", version), prompt.Bold+";"+prompt.FgWhite)
	frame("╠", "╣")
	center("расшифровка .ckz · шифрование .json · проверка структуры", prompt.FgGray)
	frame("╚", "╝")
}

func yesNo(b bool) string {
	if b {
		return ok("да")
	}
	return hint("нет")
}
