//! `SET /A` 32-bit signed two's complement integer arithmetic evaluator.
//!
//! Implements the complete C-like operator precedence hierarchy of Windows `cmd.exe`'s `SET /A`:
//! 1. `,` (Comma sequence operator — lowest precedence, left-to-right)
//! 2. `=`, `*=`, `/=`, `%=`, `+=`, `-=`, `&=`, `^=`, `|=`, `<<=`, `>>=` (Right-associative assignment)
//! 3. `|` (Bitwise OR)
//! 4. `^` (Bitwise XOR)
//! 5. `&` (Bitwise AND)
//! 6. `<<`, `>>` (Bitwise shift, shift count masked by `& 0x1F`)
//! 7. `+`, `-` (Binary addition and subtraction with 32-bit wrapping)
//! 8. `*`, `/`, `%` (Multiplication, division, modulo; checks divide-by-zero and `i32::MIN / -1` wrapping)
//! 9. `+`, `-`, `~`, `!` (Prefix unary operators)
//! 10. `( expr )` (Parenthesized grouping)
//!
//! Also supports decimal (`17`), hexadecimal (`0x11`), and octal (`021`) constants, reporting
//! `CmdError::InvalidNumber` on malformed octal literals like `08` or `09`, and implicitly
//! dereferencing bare variable names (`0` if undefined or non-numeric, supporting hex/octal values).

use crate::error::CmdError;
use crate::span::Span;

/// Lexed token inside a `SET /A` arithmetic expression.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ArithToken {
    /// Numeric literal token (`123`, `0x1A`, `077`).
    Number(String),
    /// Variable identifier token (`foo`, `_bar`).
    Ident(String),
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `,`
    Comma,
    /// `+`
    Plus,
    /// `-`
    Minus,
    /// `*`
    Star,
    /// `/`
    Slash,
    /// `%`
    Percent,
    /// `&`
    Amp,
    /// `^`
    Caret,
    /// `|`
    Pipe,
    /// `~`
    Tilde,
    /// `!`
    Bang,
    /// `<<`
    Shl,
    /// `>>`
    Shr,
    /// Assignment operators (`=`, `+=`, `-=`, `*=`, `/=`, `%=`, `&=`, `^=`, `|=`, `<<=`, `>>=`).
    Assign(AssignOp),
}

/// Assignment operator variants in `SET /A`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssignOp {
    /// `=`
    Simple,
    /// `+=`
    Add,
    /// `-=`
    Sub,
    /// `*=`
    Mul,
    /// `/=`
    Div,
    /// `%=`
    Rem,
    /// `&=`
    BitAnd,
    /// `^=`
    BitXor,
    /// `|=`
    BitOr,
    /// `<<=`
    Shl,
    /// `>>=`
    Shr,
}

/// Evaluates a `SET /A` expression string, mutating variables via `set_var` as assignments occur.
///
/// # Arguments
/// * `expr` - Raw arithmetic expression string (surrounding double quotes are stripped).
/// * `span` - Source [`Span`] of the expression for error reporting.
/// * `get_var` - Closure looking up the current string value of an environment variable.
/// * `set_var` - Closure setting the string value of an environment variable.
///
/// # Returns
/// `Ok(i32)` containing the final 32-bit signed result of the expression.
///
/// # Errors
/// Returns [`CmdError::InvalidNumber`], [`CmdError::NumberOutOfRange`], [`CmdError::DivideByZero`],
/// [`CmdError::MissingOperand`], [`CmdError::MissingOperator`], or [`CmdError::UnbalancedParensArithmetic`].
pub fn evaluate_set_a<G, S>(
    expr: &str,
    span: Span,
    get_var: G,
    mut set_var: S,
) -> Result<i32, CmdError>
where
    G: Fn(&str) -> Option<String>,
    S: FnMut(&str, i32),
{
    evaluate_set_a_dyn(expr, span, &get_var, &mut set_var)
}

/// Evaluates `SET /A` using trait-object callbacks so [`ArithParser`] is compiled once.
///
/// # Arguments
/// * `expr` - Raw arithmetic expression string.
/// * `span` - Source [`Span`] for diagnostics.
/// * `get_var` - Dynamic environment variable lookup callback.
/// * `set_var` - Dynamic environment variable mutation callback.
///
/// # Returns
/// `Ok(i32)` with the evaluated 32-bit signed result.
///
/// # Errors
/// Propagates any lexical or syntactic [`CmdError`] from tokenizing or evaluating `expr`.
fn evaluate_set_a_dyn(
    expr: &str,
    span: Span,
    get_var: &dyn Fn(&str) -> Option<String>,
    set_var: &mut dyn FnMut(&str, i32),
) -> Result<i32, CmdError> {
    let cleaned = strip_arithmetic_quotes(expr.trim());
    let tokens = tokenize_arithmetic(&cleaned, span)?;
    if tokens.is_empty() {
        return Err(CmdError::MissingOperand { span });
    }

    let mut parser = ArithParser {
        tokens: &tokens,
        pos: 0,
        span,
        get_var,
        set_var,
    };

    let result = parser.parse_comma()?;
    if let Some(tok) = parser.peek() {
        if *tok == ArithToken::RParen {
            return Err(CmdError::UnbalancedParensArithmetic { span });
        }
        return Err(CmdError::MissingOperator { span });
    }
    Ok(result)
}

/// Strips outer or segment quotes from a `SET /A` expression string.
///
/// # Arguments
/// * `raw` - Trimmed arithmetic expression text.
///
/// # Returns
/// Quote-stripped expression `String`.
fn strip_arithmetic_quotes(raw: &str) -> String {
    raw.chars().filter(|&c| c != '"').collect()
}

/// Tokenizes a `SET /A` expression string into [`ArithToken`]s.
///
/// # Arguments
/// * `input` - Quote-stripped arithmetic expression slice.
/// * `span` - Source [`Span`] reported on unrecognized characters or partial `<`/`>` operators.
///
/// # Returns
/// `Ok(Vec<ArithToken>)` containing the lexed token stream.
///
/// # Errors
/// Returns [`CmdError::MissingOperator`] on invalid single `<`, single `>`, or unrecognized symbols.
fn tokenize_arithmetic(input: &str, span: Span) -> Result<Vec<ArithToken>, CmdError> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0usize;

    while let Some(&ch) = chars.get(i) {
        if ch.is_whitespace() {
            i = i.saturating_add(1);
            continue;
        }
        if let Some((tok, consumed)) = lex_operator_token(&chars, ch, i, span)? {
            tokens.push(tok);
            i = i.saturating_add(consumed);
            continue;
        }
        if ch.is_ascii_digit() {
            let start = i;
            while chars.get(i).is_some_and(char::is_ascii_alphanumeric) {
                i = i.saturating_add(1);
            }
            let text: String = chars.get(start..i).unwrap_or(&[]).iter().collect();
            tokens.push(ArithToken::Number(text));
        } else if is_ident_char(ch) {
            let start = i;
            while chars
                .get(i)
                .is_some_and(|&nc| is_ident_char(nc) || nc.is_ascii_digit())
            {
                i = i.saturating_add(1);
            }
            let ident: String = chars.get(start..i).unwrap_or(&[]).iter().collect();
            tokens.push(ArithToken::Ident(ident));
        } else {
            return Err(CmdError::MissingOperator { span });
        }
    }

    Ok(tokens)
}

/// Attempts to lex a punctuation or assignment [`ArithToken`] starting at `ch` (`chars[i]`).
///
/// # Arguments
/// * `chars` - Full expression character slice.
/// * `ch` - Character at index `i`.
/// * `i` - Current index in `chars`.
/// * `span` - Source [`Span`] for single `<` or `>` syntax errors.
///
/// # Returns
/// `Ok(Some((ArithToken, chars_consumed)))` if `ch` starts an operator, or `Ok(None)` for digits/identifiers.
///
/// # Errors
/// Returns [`CmdError::MissingOperator`] if `<` or `>` is not doubled (`<<` / `>>`).
fn lex_operator_token(
    chars: &[char],
    ch: char,
    i: usize,
    span: Span,
) -> Result<Option<(ArithToken, usize)>, CmdError> {
    let next_eq = chars.get(i.saturating_add(1)) == Some(&'=');
    let pair = match ch {
        '(' => (ArithToken::LParen, 1),
        ')' => (ArithToken::RParen, 1),
        ',' => (ArithToken::Comma, 1),
        '~' => (ArithToken::Tilde, 1),
        '!' => (ArithToken::Bang, 1),
        '=' => (ArithToken::Assign(AssignOp::Simple), 1),
        '+' => {
            if next_eq {
                (ArithToken::Assign(AssignOp::Add), 2)
            } else {
                (ArithToken::Plus, 1)
            }
        }
        '-' => {
            if next_eq {
                (ArithToken::Assign(AssignOp::Sub), 2)
            } else {
                (ArithToken::Minus, 1)
            }
        }
        '*' => {
            if next_eq {
                (ArithToken::Assign(AssignOp::Mul), 2)
            } else {
                (ArithToken::Star, 1)
            }
        }
        '/' => {
            if next_eq {
                (ArithToken::Assign(AssignOp::Div), 2)
            } else {
                (ArithToken::Slash, 1)
            }
        }
        '%' => {
            if next_eq {
                (ArithToken::Assign(AssignOp::Rem), 2)
            } else {
                (ArithToken::Percent, 1)
            }
        }
        '&' => {
            if next_eq {
                (ArithToken::Assign(AssignOp::BitAnd), 2)
            } else {
                (ArithToken::Amp, 1)
            }
        }
        '^' => {
            if next_eq {
                (ArithToken::Assign(AssignOp::BitXor), 2)
            } else {
                (ArithToken::Caret, 1)
            }
        }
        '|' => {
            if next_eq {
                (ArithToken::Assign(AssignOp::BitOr), 2)
            } else {
                (ArithToken::Pipe, 1)
            }
        }
        '<' => {
            if chars.get(i.saturating_add(1)) != Some(&'<') {
                return Err(CmdError::MissingOperator { span });
            }
            if chars.get(i.saturating_add(2)) == Some(&'=') {
                (ArithToken::Assign(AssignOp::Shl), 3)
            } else {
                (ArithToken::Shl, 2)
            }
        }
        '>' => {
            if chars.get(i.saturating_add(1)) != Some(&'>') {
                return Err(CmdError::MissingOperator { span });
            }
            if chars.get(i.saturating_add(2)) == Some(&'=') {
                (ArithToken::Assign(AssignOp::Shr), 3)
            } else {
                (ArithToken::Shr, 2)
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(pair))
}

/// Checks if `ch` is a valid non-digit variable identifier character inside `SET /A`.
///
/// # Arguments
/// * `ch` - Candidate character.
///
/// # Returns
/// `true` if `ch` may start or continue a variable identifier in `SET /A`.
const fn is_ident_char(ch: char) -> bool {
    ch.is_ascii_alphabetic() || matches!(ch, '_' | '$' | '#' | '@' | '.' | '[' | ']')
}

/// Parses a numeric token (`17`, `0x11`, `021`) into an `i32`.
///
/// # Arguments
/// * `text` - Raw number literal string.
/// * `span` - Source [`Span`].
///
/// # Returns
/// `Ok(i32)` if valid.
///
/// # Errors
/// Returns [`CmdError::InvalidNumber`] on invalid base digits (such as octal `08` or `09`),
/// or [`CmdError::NumberOutOfRange`] if the value exceeds 32-bit precision.
pub fn parse_arith_number(text: &str, span: Span) -> Result<i32, CmdError> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(CmdError::InvalidNumber {
                span,
                text: text.to_owned(),
            });
        }
        let val =
            u32::from_str_radix(hex, 16).map_err(|_parse_err| CmdError::NumberOutOfRange {
                span,
                text: text.to_owned(),
            })?;
        return Ok(val.cast_signed());
    }

    if text.len() > 1 && text.starts_with('0') {
        if !text.chars().all(|c| ('0'..='7').contains(&c)) {
            return Err(CmdError::InvalidNumber {
                span,
                text: text.to_owned(),
            });
        }
        let val =
            u32::from_str_radix(text, 8).map_err(|_parse_err| CmdError::NumberOutOfRange {
                span,
                text: text.to_owned(),
            })?;
        return Ok(val.cast_signed());
    }

    if !text.chars().all(|c| c.is_ascii_digit()) {
        return Err(CmdError::InvalidNumber {
            span,
            text: text.to_owned(),
        });
    }

    let val = text
        .parse::<u32>()
        .map_err(|_parse_err| CmdError::NumberOutOfRange {
            span,
            text: text.to_owned(),
        })?;
    Ok(val.cast_signed())
}

/// Recursive-descent parser state for `SET /A`.
struct ArithParser<'a> {
    /// Token slice.
    tokens: &'a [ArithToken],
    /// Current token index.
    pos: usize,
    /// Expression span.
    span: Span,
    /// Variable lookup closure.
    get_var: &'a dyn Fn(&str) -> Option<String>,
    /// Variable assignment closure.
    set_var: &'a mut dyn FnMut(&str, i32),
}

impl ArithParser<'_> {
    /// Peeks at the current token without advancing.
    ///
    /// # Returns
    /// `Some(&ArithToken)` at `self.pos`, or `None` at end of stream.
    fn peek(&self) -> Option<&ArithToken> {
        self.tokens.get(self.pos)
    }

    /// Advances the token cursor by 1.
    const fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    /// Reads the current `i32` value of a variable by name (`0` if undefined, blank, or non-numeric).
    ///
    /// # Arguments
    /// * `name` - Variable identifier to dereference.
    ///
    /// # Returns
    /// `Ok(i32)` parsed in decimal, `0x` hex, or `0` octal after trimming whitespace.
    ///
    /// # Errors
    /// Returns [`CmdError::InvalidNumber`] or [`CmdError::NumberOutOfRange`] on malformed numeric contents.
    fn read_var_value(&self, name: &str) -> Result<i32, CmdError> {
        let Some(raw_val) = (self.get_var)(name) else {
            return Ok(0);
        };
        let trimmed = raw_val.trim();
        if trimmed.is_empty() {
            return Ok(0);
        }
        let (sign, rest) = trimmed.strip_prefix('-').map_or_else(
            || {
                trimmed
                    .strip_prefix('+')
                    .map_or((1i32, trimmed), |after_plus| (1i32, after_plus.trim()))
            },
            |after_minus| (-1i32, after_minus.trim()),
        );
        if rest.starts_with(|c: char| c.is_ascii_digit()) {
            let parsed = parse_arith_number(rest, self.span)?;
            Ok(parsed.wrapping_mul(sign))
        } else {
            Ok(0)
        }
    }

    /// Level 1: Comma sequence `expr , expr`.
    ///
    /// # Returns
    /// `Ok(i32)` of the rightmost comma-separated expression.
    ///
    /// # Errors
    /// Propagates any [`CmdError`] from sub-expressions.
    fn parse_comma(&mut self) -> Result<i32, CmdError> {
        let mut val = self.parse_assign()?;
        while self.peek() == Some(&ArithToken::Comma) {
            self.bump();
            val = self.parse_assign()?;
        }
        Ok(val)
    }

    /// Level 2: Right-associative assignment `ident OP= expr`.
    ///
    /// # Returns
    /// `Ok(i32)` with the assigned or evaluated value.
    ///
    /// # Errors
    /// Returns [`CmdError::MissingOperand`] if an assignment operator has a non-lvalue left-hand side.
    fn parse_assign(&mut self) -> Result<i32, CmdError> {
        if let Some(ArithToken::Ident(name)) = self.peek().cloned()
            && let Some(ArithToken::Assign(op)) =
                self.tokens.get(self.pos.saturating_add(1)).cloned()
        {
            self.bump();
            self.bump();
            let rhs = self.parse_assign()?;
            let lhs = if op == AssignOp::Simple {
                0
            } else {
                self.read_var_value(&name)?
            };
            let new_val = apply_assign_op(lhs, op, rhs, self.span)?;
            (self.set_var)(&name, new_val);
            return Ok(new_val);
        }

        let val = self.parse_bit_or()?;
        if matches!(self.peek(), Some(ArithToken::Assign(_))) {
            return Err(CmdError::MissingOperand { span: self.span });
        }
        Ok(val)
    }

    /// Level 3: Bitwise OR `|`.
    ///
    /// # Returns
    /// `Ok(i32)` bitwise-OR result.
    ///
    /// # Errors
    /// Propagates any [`CmdError`] from operands.
    fn parse_bit_or(&mut self) -> Result<i32, CmdError> {
        let mut val = self.parse_bit_xor()?;
        while self.peek() == Some(&ArithToken::Pipe) {
            self.bump();
            let rhs = self.parse_bit_xor()?;
            val |= rhs;
        }
        Ok(val)
    }

    /// Level 4: Bitwise XOR `^`.
    ///
    /// # Returns
    /// `Ok(i32)` bitwise-XOR result.
    ///
    /// # Errors
    /// Propagates any [`CmdError`] from operands.
    fn parse_bit_xor(&mut self) -> Result<i32, CmdError> {
        let mut val = self.parse_bit_and()?;
        while self.peek() == Some(&ArithToken::Caret) {
            self.bump();
            let rhs = self.parse_bit_and()?;
            val ^= rhs;
        }
        Ok(val)
    }

    /// Level 5: Bitwise AND `&`.
    ///
    /// # Returns
    /// `Ok(i32)` bitwise-AND result.
    ///
    /// # Errors
    /// Propagates any [`CmdError`] from operands.
    fn parse_bit_and(&mut self) -> Result<i32, CmdError> {
        let mut val = self.parse_shift()?;
        while self.peek() == Some(&ArithToken::Amp) {
            self.bump();
            let rhs = self.parse_shift()?;
            val &= rhs;
        }
        Ok(val)
    }

    /// Level 6: Bitwise shift `<<` and `>>` (shift amount masked to `0..=31`).
    ///
    /// # Returns
    /// `Ok(i32)` shifted result.
    ///
    /// # Errors
    /// Propagates any [`CmdError`] from operands.
    fn parse_shift(&mut self) -> Result<i32, CmdError> {
        let mut val = self.parse_add_sub()?;
        while let Some(tok) = self.peek().cloned() {
            if tok == ArithToken::Shl {
                self.bump();
                let rhs = self.parse_add_sub()?;
                let shift = rhs.cast_unsigned() & 0x1F;
                val = val.wrapping_shl(shift);
            } else if tok == ArithToken::Shr {
                self.bump();
                let rhs = self.parse_add_sub()?;
                let shift = rhs.cast_unsigned() & 0x1F;
                val = val.wrapping_shr(shift);
            } else {
                break;
            }
        }
        Ok(val)
    }

    /// Level 7: Wrapping 32-bit addition `+` and subtraction `-`.
    ///
    /// # Returns
    /// `Ok(i32)` sum or difference.
    ///
    /// # Errors
    /// Propagates any [`CmdError`] from operands.
    fn parse_add_sub(&mut self) -> Result<i32, CmdError> {
        let mut val = self.parse_mul_div()?;
        while let Some(tok) = self.peek().cloned() {
            if tok == ArithToken::Plus {
                self.bump();
                let rhs = self.parse_mul_div()?;
                val = val.wrapping_add(rhs);
            } else if tok == ArithToken::Minus {
                self.bump();
                let rhs = self.parse_mul_div()?;
                val = val.wrapping_sub(rhs);
            } else {
                break;
            }
        }
        Ok(val)
    }

    /// Level 8: Multiplication `*`, division `/`, and modulo `%` (handling `0` and `i32::MIN / -1` safely).
    ///
    /// # Returns
    /// `Ok(i32)` product, quotient, or remainder.
    ///
    /// # Errors
    /// Returns [`CmdError::DivideByZero`] when `rhs == 0`.
    fn parse_mul_div(&mut self) -> Result<i32, CmdError> {
        let mut val = self.parse_unary()?;
        while let Some(tok) = self.peek().cloned() {
            if tok == ArithToken::Star {
                self.bump();
                let rhs = self.parse_unary()?;
                val = val.wrapping_mul(rhs);
            } else if tok == ArithToken::Slash {
                self.bump();
                let rhs = self.parse_unary()?;
                val = checked_wrapping_div(val, rhs, self.span)?;
            } else if tok == ArithToken::Percent {
                self.bump();
                let rhs = self.parse_unary()?;
                val = checked_wrapping_rem(val, rhs, self.span)?;
            } else {
                break;
            }
        }
        Ok(val)
    }

    /// Level 9: Prefix unary operators `+`, `-`, `~`, `!`.
    ///
    /// # Returns
    /// `Ok(i32)` unary result.
    ///
    /// # Errors
    /// Propagates any [`CmdError`] from the operand.
    fn parse_unary(&mut self) -> Result<i32, CmdError> {
        match self.peek().cloned() {
            Some(ArithToken::Plus) => {
                self.bump();
                self.parse_unary()
            }
            Some(ArithToken::Minus) => {
                self.bump();
                let v = self.parse_unary()?;
                Ok(v.wrapping_neg())
            }
            Some(ArithToken::Tilde) => {
                self.bump();
                let v = self.parse_unary()?;
                Ok(!v)
            }
            Some(ArithToken::Bang) => {
                self.bump();
                let v = self.parse_unary()?;
                Ok(i32::from(v == 0))
            }
            _ => self.parse_primary(),
        }
    }

    /// Level 10: Primary expressions `( expr )`, number literals, and variable identifiers.
    ///
    /// # Returns
    /// `Ok(i32)` primary value.
    ///
    /// # Errors
    /// Returns [`CmdError::MissingOperand`] or [`CmdError::UnbalancedParensArithmetic`] on malformed syntax.
    fn parse_primary(&mut self) -> Result<i32, CmdError> {
        match self.peek().cloned() {
            Some(ArithToken::LParen) => {
                self.bump();
                if self.peek() == Some(&ArithToken::RParen) {
                    return Err(CmdError::MissingOperand { span: self.span });
                }
                let val = self.parse_comma()?;
                if self.peek() == Some(&ArithToken::RParen) {
                    self.bump();
                    Ok(val)
                } else {
                    Err(CmdError::UnbalancedParensArithmetic { span: self.span })
                }
            }
            Some(ArithToken::Number(text)) => {
                self.bump();
                parse_arith_number(&text, self.span)
            }
            Some(ArithToken::Ident(name)) => {
                self.bump();
                self.read_var_value(&name)
            }
            Some(ArithToken::RParen) => {
                Err(CmdError::UnbalancedParensArithmetic { span: self.span })
            }
            _ => Err(CmdError::MissingOperand { span: self.span }),
        }
    }
}

/// Divides `lhs` by `rhs` using 32-bit two's-complement wrapping (`i32::MIN / -1 == i32::MIN`).
///
/// # Arguments
/// * `lhs` - Dividend.
/// * `rhs` - Divisor.
/// * `span` - Source [`Span`] reported when `rhs == 0`.
///
/// # Returns
/// `Ok(i32)` wrapping quotient.
///
/// # Errors
/// Returns [`CmdError::DivideByZero`] when `rhs == 0`.
const fn checked_wrapping_div(lhs: i32, rhs: i32, span: Span) -> Result<i32, CmdError> {
    if rhs == 0 {
        return Err(CmdError::DivideByZero { span });
    }
    match lhs.checked_div(rhs) {
        Some(q) => Ok(q),
        None => Ok(i32::MIN),
    }
}

/// Computes `lhs % rhs` using 32-bit two's-complement wrapping (`i32::MIN % -1 == 0`).
///
/// # Arguments
/// * `lhs` - Dividend.
/// * `rhs` - Divisor.
/// * `span` - Source [`Span`] reported when `rhs == 0`.
///
/// # Returns
/// `Ok(i32)` wrapping remainder.
///
/// # Errors
/// Returns [`CmdError::DivideByZero`] when `rhs == 0`.
const fn checked_wrapping_rem(lhs: i32, rhs: i32, span: Span) -> Result<i32, CmdError> {
    if rhs == 0 {
        return Err(CmdError::DivideByZero { span });
    }
    match lhs.checked_rem(rhs) {
        Some(r) => Ok(r),
        None => Ok(0),
    }
}

/// Applies a compound assignment operator (`+=`, `/=`, etc.) to `lhs` and `rhs`.
///
/// # Arguments
/// * `lhs` - Current variable value (`0` for simple `=`).
/// * `op` - [`AssignOp`] variant.
/// * `rhs` - Right-hand expression value.
/// * `span` - Source [`Span`] for divide-by-zero errors.
///
/// # Returns
/// `Ok(i32)` new variable value.
///
/// # Errors
/// Returns [`CmdError::DivideByZero`] on `/= 0` or `%= 0`.
const fn apply_assign_op(lhs: i32, op: AssignOp, rhs: i32, span: Span) -> Result<i32, CmdError> {
    match op {
        AssignOp::Simple => Ok(rhs),
        AssignOp::Add => Ok(lhs.wrapping_add(rhs)),
        AssignOp::Sub => Ok(lhs.wrapping_sub(rhs)),
        AssignOp::Mul => Ok(lhs.wrapping_mul(rhs)),
        AssignOp::Div => checked_wrapping_div(lhs, rhs, span),
        AssignOp::Rem => checked_wrapping_rem(lhs, rhs, span),
        AssignOp::BitAnd => Ok(lhs & rhs),
        AssignOp::BitXor => Ok(lhs ^ rhs),
        AssignOp::BitOr => Ok(lhs | rhs),
        AssignOp::Shl => Ok(lhs.wrapping_shl(rhs.cast_unsigned() & 0x1F)),
        AssignOp::Shr => Ok(lhs.wrapping_shr(rhs.cast_unsigned() & 0x1F)),
    }
}

#[cfg(test)]
/// Unit tests for `SET /A` 32-bit signed two's-complement arithmetic and operator precedence.
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// Verifies `SET /A` operator precedence, variable dereferencing, compound assignments, and `i32::MIN` wrapping.
    #[test]
    fn test_all_arithmetic_operators_precedence_and_signed_min_overflow() {
        let vars: RefCell<BTreeMap<String, String>> = RefCell::new(BTreeMap::new());
        vars.borrow_mut().insert("INIT".to_owned(), "-5".to_owned());
        vars.borrow_mut()
            .insert("PLUS_VAL".to_owned(), "+7".to_owned());
        vars.borrow_mut()
            .insert("HEX_VAR".to_owned(), " 0x10 ".to_owned());
        vars.borrow_mut()
            .insert("OCT_VAR".to_owned(), " -010 ".to_owned());
        vars.borrow_mut()
            .insert("EMPTY".to_owned(), "   ".to_owned());
        vars.borrow_mut()
            .insert("TEXT".to_owned(), "non_num".to_owned());

        let eval = |expr: &str| -> Result<i32, CmdError> {
            evaluate_set_a(
                expr,
                Span::dummy(),
                |k| vars.borrow().get(&k.to_ascii_uppercase()).cloned(),
                |k, v| {
                    vars.borrow_mut()
                        .insert(k.to_ascii_uppercase(), v.to_string());
                },
            )
        };

        assert_eq!(eval("1 + 2 * 3"), Ok(7));
        assert_eq!(eval("(1 + 2) * 3"), Ok(9));
        assert_eq!(eval("+10 - -5"), Ok(15));
        assert_eq!(eval("~0"), Ok(-1));
        assert_eq!(eval("!0, !5"), Ok(0));
        assert_eq!(eval("0x10 + 0X10 + 010 + 10"), Ok(50));
        assert_eq!(eval("1 << 4 >> 2"), Ok(4));
        assert_eq!(eval("7 & 3 | 8 ^ 2"), Ok(11));
        assert_eq!(eval("17 / 5 + 17 % 5"), Ok(5));
        assert_eq!(eval("INIT + PLUS_VAL + UNDEF + EMPTY + TEXT"), Ok(2));
        assert_eq!(eval("HEX_VAR + OCT_VAR"), Ok(8));

        // Signed two's-complement overflow trap (`i32::MIN / -1` and `i32::MIN % -1`)
        assert_eq!(eval("-2147483648 / -1"), Ok(i32::MIN));
        assert_eq!(eval("-2147483648 % -1"), Ok(0));

        // Compound assignments and comma sequencing
        assert_eq!(eval("a=10, a+=5, a-=3, a*=2, a/=4, a%=4"), Ok(2));
        assert_eq!(eval("b=1, b<<=3, b>>=1, b|=2, b&=6, b^=1"), Ok(7));
    }

    /// Verifies `SET /A` error reporting on unbalanced parentheses, missing operands, divide-by-zero, and invalid radices.
    #[test]
    fn test_arithmetic_error_conditions() {
        let vars: RefCell<BTreeMap<String, String>> = RefCell::new(BTreeMap::new());
        vars.borrow_mut()
            .insert("BAD_OCT".to_owned(), "08".to_owned());

        let eval = |expr: &str| -> Result<i32, CmdError> {
            evaluate_set_a(
                expr,
                Span::dummy(),
                |k| vars.borrow().get(&k.to_ascii_uppercase()).cloned(),
                |k, v| {
                    vars.borrow_mut().insert(k.to_owned(), v.to_string());
                },
            )
        };

        assert_eq!(eval("var1 = 5"), Ok(5));
        assert_eq!(eval("x = 5"), Ok(5));
        assert!(parse_arith_number("abc", Span::dummy()).is_err());
        for bad_expr in [
            "",
            "1 +",
            "()",
            "1 = 2",
            "1 2",
            "1 < 2",
            "1 > 2",
            "1 ? 2",
            "(1 + 2",
            "1 + 2)",
            ")",
            "10 / 0",
            "10 % 0",
            "x /= 0",
            "x %= 0",
            "08",
            "09",
            "0x",
            "0xZZ",
            "12abc",
            "99999999999999",
            "0xFFFFFFFFF",
            "0777777777777",
            "BAD_OCT",
            "1, +",
            "BAD_OCT += 1",
            "1 | +",
            "1 ^ +",
            "1 & +",
            "1 << +",
            "1 >> +",
            "1 - +",
            "1 * +",
            "1 / +",
            "1 % +",
            "- +",
            "~ +",
            "! +",
            "(1 + )",
        ] {
            assert!(eval(bad_expr).is_err(), "Expected error for: {bad_expr}");
        }
    }
}
