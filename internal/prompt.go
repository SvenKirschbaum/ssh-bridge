package internal

import (
	"gioui.org/app"
	"gioui.org/font/gofont"
	"gioui.org/io/system"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"image/color"
)

type (
	// C quick alias for Context.
	C = layout.Context
	// D quick alias for Dimensions.
	D = layout.Dimensions
)

type Prompt struct {
	config PromptConfig
	w      *app.Window
	th     *material.Theme
	editor widget.Editor
	list   widget.List
	Text   []string
	Output chan string
}

type PromptConfig struct {
	HideInput bool
	InputHint string
}

func NewPrompt(config PromptConfig) Prompt {
	mask := rune(0)

	if config.HideInput {
		mask = '*'
	}

	prompt := Prompt{
		config: config,
		w:      app.NewWindow(app.Title("SSH-Bridge")),
		th:     material.NewTheme(gofont.Collection()),
		editor: widget.Editor{
			SingleLine: true,
			Submit:     true,
			Mask:       mask,
		},
		Output: make(chan string),
		Text:   []string{},
	}

	prompt.w.Option(app.MaxSize(unit.Dp(400), unit.Dp(100)))

	go prompt.loop()

	prompt.w.Raise()
	prompt.editor.Focus()

	return prompt
}

func (p *Prompt) loop() {
	var ops op.Ops
	for {
		e := <-p.w.Events()

		switch e := e.(type) {
		case system.DestroyEvent:
			p.w.Close()
			close(p.Output)
			break
		case system.FrameEvent:
			e.Frame(p.frame(layout.NewContext(&ops, e)))
		}
	}
}

func (p *Prompt) Update() {
	p.w.Invalidate()
}

// frame lays out the entire frame and returns the reusltant ops buffer.
func (p *Prompt) frame(gtx C) *op.Ops {
	for _, event := range p.editor.Events() {
		if submitEvent, ok := event.(widget.SubmitEvent); ok && submitEvent.Text != "" {
			p.w.Close()
			select {
			case p.Output <- submitEvent.Text:
			default:
			}
		}
	}

	layout.Inset{
		Top:    unit.Dp(30),
		Right:  unit.Dp(20),
		Bottom: unit.Dp(30),
		Left:   unit.Dp(20),
	}.Layout(gtx, func(gtx C) D {
		return widget.Border{
			Color: blue,
			Width: unit.Dp(1),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.UniformInset(unit.Dp(6)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				gtx.Constraints.Min.Y = 0
				return material.Editor(p.th, &p.editor, p.config.InputHint).Layout(gtx)
			})
		})
	})

	return gtx.Ops
}

var red = color.NRGBA{R: 0xC0, G: 0x40, B: 0x40, A: 0xFF}
var blue = color.NRGBA{R: 0x40, G: 0x40, B: 0xC0, A: 0xFF}
