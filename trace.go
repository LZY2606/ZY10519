// Copyright The envconfig Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package envconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// TraceSource describes where a field's candidate value came from, as observed
// by the decoder.
type TraceSource string

const (
	// SourceNone is the zero value; no source has been recorded yet.
	SourceNone TraceSource = ""

	// SourceEnvironment means the value was returned by the [Lookuper] for the
	// field's environment key.
	SourceEnvironment TraceSource = "environment"

	// SourceDefault means the value came from the "default" tag option because
	// the environment key was unset.
	SourceDefault TraceSource = "default"

	// SourceUnset means neither the environment nor a default value supplied a
	// value for the field.
	SourceUnset TraceSource = "unset"

	// SourceNested marks struct fields that are only traversed to reach their
	// children; the field itself has no environment value.
	SourceNested TraceSource = "nested"
)

// TraceStatus is the terminal outcome recorded for a field.
type TraceStatus string

const (
	// StatusSet means a value was decoded and assigned to the field.
	StatusSet TraceStatus = "set"

	// StatusUnset means no value was available and the field kept its zero
	// value (subject to pointer and noinit rules).
	StatusUnset TraceStatus = "unset"

	// StatusSkipped means the field was not touched because it already held a
	// non-zero value and "overwrite" was not enabled.
	StatusSkipped TraceStatus = "skipped"

	// StatusNested means the field is a struct that was traversed for its
	// children rather than decoded itself.
	StatusNested TraceStatus = "nested"

	// StatusError means processing the field failed. The TraceEvent.Err field
	// carries the sanitized failure details.
	StatusError TraceStatus = "error"
)

// TraceMutator records one mutator stage observed while resolving a field. It
// never contains values: mutator inputs and outputs are deliberately excluded
// so the trace cannot leak secrets through it.
type TraceMutator struct {
	// Index is the zero-based position of the mutator in [Config.Mutators].
	Index int

	// Name is a stable, human-readable name derived from the mutator's concrete
	// type.
	Name string

	// Changed reports whether the mutator returned a value different from its
	// current input value.
	Changed bool

	// Err is the error text returned by the mutator, or empty on success. When
	// the enclosing event is sensitive, only the error type or a known sentinel
	// message is retained.
	Err string
}

// TraceEvent is the field-level diagnostic emitted once per processed field.
//
// Values are never included directly. For non-sensitive fields ValueType,
// ValueLen and ValueFingerprint describe the resolved value; for sensitive
// fields those value descriptors are withheld entirely.
type TraceEvent struct {
	// Path is the stable dot-separated path of Go field names from the root
	// config struct to the field (for example "Database.Port"). Fields of
	// anonymous embedded structs are promoted, so their path is rooted at the
	// embedding struct without an extra segment.
	Path string

	// Field is the Go field name of the current field.
	Field string

	// FieldType is the Go type of the field as reported by
	// [reflect.Type.String].
	FieldType string

	// CandidateKeys lists the environment keys considered for the field, in
	// lookup order. The first entry is the key as declared on the tag; when the
	// active [Lookuper] rewrites keys (for example through [PrefixLookuper]),
	// the fully-resolved key is appended without duplicates. It is empty for
	// nested struct containers.
	CandidateKeys []string

	// Source is where the resolved value originated.
	Source TraceSource

	// Mutators lists the mutator stages that ran for the field, in execution
	// order, including stages that failed.
	Mutators []TraceMutator

	// Decoder is the category of decoder that ultimately handled the value, or
	// DecoderBuiltin for native type conversion, DecoderNested for traversed
	// structs, and DecoderNone when no decoder ran.
	Decoder DecoderKind

	// Status is the terminal processing status of the field.
	Status TraceStatus

	// ValueType is the Go type of the resolved value ("string" for environment
	// values, since lookupers always return strings).
	ValueType string

	// ValueLen is the length in bytes of the resolved value after mutators ran.
	// It is -1 when the value was withheld (sensitive fields) or when no value
	// was resolved.
	ValueLen int

	// ValueFingerprint is a short, non-reversible fingerprint (the first 8 hex
	// characters of the SHA-256 digest) of the resolved value. It is empty for
	// sensitive fields, allowing callers to correlate identical values without
	// learning them.
	ValueFingerprint string

	// Sensitive reports that the field (or an ancestor struct) carried the
	// "sensitive" tag option. Sensitive events never carry value descriptors or
	// verbatim error messages.
	Sensitive bool

	// Err is the sanitized processing error. It is empty unless Status is
	// [StatusError]. For sensitive fields it is reduced to a known envconfig
	// sentinel message or the concrete error type name, never the raw text.
	Err string
}

// TraceReceiver receives field-level trace events while a config is being
// processed. Exactly one event is delivered per processed field, including
// fields that fail, so failures retain their source context.
//
// A receiver runs synchronously on the processing goroutine, after the field's
// outcome is known but before processing returns. Returning an error, or
// panicking, never aborts decoding and never changes the resulting config: the
// failure is isolated, recorded, and joined into the error returned by
// [ProcessWith] as a [TraceReceiverError].
type TraceReceiver interface {
	ReceiveTraceEvent(ctx context.Context, event *TraceEvent) error
}

var _ TraceReceiver = (TraceReceiverFunc)(nil)

// TraceReceiverFunc adapts a function into a [TraceReceiver].
type TraceReceiverFunc func(ctx context.Context, event *TraceEvent) error

// ReceiveTraceEvent implements [TraceReceiver].
func (f TraceReceiverFunc) ReceiveTraceEvent(ctx context.Context, event *TraceEvent) error {
	return f(ctx, event)
}

// TraceReceiverError wraps a failure raised by a [TraceReceiver]. Receiver
// failures are isolated from decoding: they do not stop processing and do not
// alter the config, but they are still surfaced so diagnostic failures cannot
// be silently ignored.
type TraceReceiverError struct {
	// Path is the Path of the [TraceEvent] being delivered when the receiver
	// failed.
	Path string

	// Receiver is the stable name of the receiver's concrete type.
	Receiver string

	// Err is the failure returned by the receiver, or the recovered panic.
	Err error
}

// Error implements error.
func (e *TraceReceiverError) Error() string {
	return fmt.Sprintf("trace receiver %q failed for %q: %s", e.Receiver, e.Path, e.Err)
}

// Unwrap returns the underlying receiver error.
func (e *TraceReceiverError) Unwrap() error {
	return e.Err
}

// traceState carries the active receiver and the receiver failures collected
// during a single ProcessWith run, including across nested struct recursion.
type traceState struct {
	receiver TraceReceiver
	errs     []error
}

// emit finalizes and delivers one event. Receiver errors and panics are
// captured here so they cannot change decoding results or prevent sibling
// fields from being traced.
func (ts *traceState) emit(ctx context.Context, ev *TraceEvent) {
	if ts == nil || ts.receiver == nil {
		return
	}

	// Copy slices so a receiver cannot mutate the data captured for later
	// events or the evidence retained on errors.
	if ev.CandidateKeys != nil {
		ev.CandidateKeys = slicesClone(ev.CandidateKeys)
	}
	if ev.Mutators != nil {
		ev.Mutators = slicesClone(ev.Mutators)
	}

	defer func() {
		if r := recover(); r != nil {
			ts.errs = append(ts.errs, &TraceReceiverError{
				Path:     ev.Path,
				Receiver: receiverName(ts.receiver),
				Err:      fmt.Errorf("recovered panic: %v", r),
			})
		}
	}()

	if err := ts.receiver.ReceiveTraceEvent(ctx, ev); err != nil {
		ts.errs = append(ts.errs, &TraceReceiverError{
			Path:     ev.Path,
			Receiver: receiverName(ts.receiver),
			Err:      err,
		})
	}
}

// receiverError joins all receiver failures collected during the run, or
// returns nil when the receiver never failed.
func (ts *traceState) receiverError() error {
	if ts == nil || len(ts.errs) == 0 {
		return nil
	}
	return errors.Join(ts.errs...)
}

func receiverName(r TraceReceiver) string {
	return fmt.Sprintf("%T", r)
}

// fieldTrace accumulates the evidence for one field and produces the single
// event delivered when the field finishes.
type fieldTrace struct {
	event       TraceEvent
	decodedVal  string
	haveValue   bool
	sensitive   bool
	decoderKind DecoderKind
}

// newFieldTrace builds the trace for a field, seeding identity and the keys
// that will be considered. parentSensitive is whether an ancestor struct
// carried the "sensitive" option.
func newFieldTrace(fieldName, fieldType string, parentPath []string, parentSensitive bool, localSensitive bool, localKey string, lookuper Lookuper) *fieldTrace {
	sensitive := parentSensitive || localSensitive
	path := strings.Join(parentPath, ".")

	ft := &fieldTrace{
		event: TraceEvent{
			Path:      path,
			Field:     fieldName,
			FieldType: fieldType,
			Source:    SourceNone,
			Decoder:   DecoderNone,
			Status:    StatusUnset,
			ValueLen:  -1,
			Sensitive: sensitive,
		},
		sensitive: sensitive,
	}

	if localKey != "" {
		ft.event.CandidateKeys = appendCandidateKey(nil, localKey)
		if keyer, ok := lookuper.(keyedLookuper); ok {
			ft.event.CandidateKeys = appendCandidateKey(ft.event.CandidateKeys, keyer.Key(localKey))
		}
	}

	return ft
}

// appendCandidateKey appends key unless it duplicates the last entry.
func appendCandidateKey(keys []string, key string) []string {
	if key == "" {
		return keys
	}
	if len(keys) > 0 && keys[len(keys)-1] == key {
		return keys
	}
	return append(keys, key)
}

// markLookup records the source and value observed by the lookup. val is only
// retained long enough to fingerprint at emit time; it is never exposed on the
// event.
func (ft *fieldTrace) markLookup(val string, found, usedDefault bool) {
	switch {
	case found:
		ft.event.Source = SourceEnvironment
		ft.decodedVal = val
		ft.haveValue = true
	case usedDefault:
		ft.event.Source = SourceDefault
		ft.decodedVal = val
		ft.haveValue = true
	default:
		ft.event.Source = SourceUnset
		ft.decodedVal = ""
		ft.haveValue = false
	}
}

// markNested marks the field as a traversed struct container.
func (ft *fieldTrace) markNested() {
	ft.event.Source = SourceNested
	ft.event.Status = StatusNested
	ft.decoderKind = DecoderNested
	ft.event.Decoder = DecoderNested
}

// recordMutator appends one mutator stage.
func (ft *fieldTrace) recordMutator(index int, name string, before, after string, err error) {
	stage := TraceMutator{
		Index:   index,
		Name:    name,
		Changed: before != after,
	}
	if err != nil {
		stage.Err = ft.sanitizeError(err)
	}
	ft.event.Mutators = append(ft.event.Mutators, stage)
}

// finalize produces the immutable event for delivery. status and decoder may
// be upgraded from what was collected while walking the field.
func (ft *fieldTrace) finalize(status TraceStatus, decoder DecoderKind, processErr error) *TraceEvent {
	ev := &ft.event

	if status != "" {
		ev.Status = status
	}
	if decoder != DecoderNone {
		ev.Decoder = decoder
	} else if ft.decoderKind != DecoderNone {
		ev.Decoder = ft.decoderKind
	}

	if processErr != nil {
		ev.Status = StatusError
		ev.Err = ft.sanitizeError(processErr)
	}

	// Value descriptors only survive for non-sensitive fields that resolved a
	// value. Struct containers and unset fields withhold them.
	if ft.haveValue && !ft.sensitive && ev.Source != SourceNested {
		ev.ValueType = "string"
		ev.ValueLen = len(ft.decodedVal)
		sum := sha256.Sum256([]byte(ft.decodedVal))
		ev.ValueFingerprint = hex.EncodeToString(sum[:])[:8]
	}

	return ev
}

// sanitizeError renders an error safe to attach to an event. For sensitive
// fields the raw text may contain the secret (a decoder might echo it, for
// example), so it is reduced to a known sentinel message or the concrete error
// type name.
func (ft *fieldTrace) sanitizeError(err error) string {
	if !ft.sensitive {
		return err.Error()
	}

	var iErr internalError
	if errors.As(err, &iErr) {
		// Sentinels are fixed library strings (for example "missing required
		// value: KEY") and do not include values.
		return string(iErr)
	}
	return fmt.Sprintf("%T", err)
}

func slicesClone[T any](s []T) []T {
	out := make([]T, len(s))
	copy(out, s)
	return out
}
