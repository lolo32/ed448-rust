use core::{
    fmt,
    ops::{Add, Div, Mul, Neg, Sub},
};

use lazy_static::lazy_static;
use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};

use crate::{array_to_key, Ed448Error, KEY_LENGTH};

lazy_static! {
    // 2 ^ 448 - 2 ^224 - 1
    static ref p: BigInt = BigInt::from(2).pow(448).sub(BigInt::from(2).pow(224)) - 1;
    static ref d: Field = Field::new(BigInt::from(-39081));
    static ref f0: Field = Field::new(BigInt::zero());
    static ref f1: Field = Field::new(BigInt::one());
    static ref xb: Field = Field::new(BigInt::from_bytes_be(
        Sign::Plus,
        &[
            0x4F, 0x19, 0x70, 0xC6, 0x6B, 0xED, 0x0D, 0xED, 0x22, 0x1D, 0x15, 0xA6, 0x22, 0xBF,
            0x36, 0xDA, 0x9E, 0x14, 0x65, 0x70, 0x47, 0x0F, 0x17, 0x67, 0xEA, 0x6D, 0xE3, 0x24,
            0xA3, 0xD3, 0xA4, 0x64, 0x12, 0xAE, 0x1A, 0xF7, 0x2A, 0xB6, 0x65, 0x11, 0x43, 0x3B,
            0x80, 0xE1, 0x8B, 0x00, 0x93, 0x8E, 0x26, 0x26, 0xA8, 0x2B, 0xC7, 0x0C, 0xC0, 0x5E,
        ]
    ));
    static ref yb: Field = Field::new(BigInt::from_bytes_be(
        Sign::Plus,
        &[
            0x69, 0x3F, 0x46, 0x71, 0x6E, 0xB6, 0xBC, 0x24, 0x88, 0x76, 0x20, 0x37, 0x56, 0xC9,
            0xC7, 0x62, 0x4B, 0xEA, 0x73, 0x73, 0x6C, 0xA3, 0x98, 0x40, 0x87, 0x78, 0x9C, 0x1E,
            0x05, 0xA0, 0xC2, 0xD7, 0x3A, 0xD3, 0xFF, 0x1C, 0xE6, 0x7C, 0x39, 0xC4, 0xFD, 0xBD,
            0x13, 0x2C, 0x4E, 0xD7, 0xC8, 0xAD, 0x98, 0x08, 0x79, 0x5B, 0xF2, 0x30, 0xFA, 0x14,
        ]
    ));

    static ref l: BigInt = BigInt::from_bytes_be(
        Sign::Plus,
        &[
            0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x7c, 0xca, 0x23, 0xe9, 0xc4, 0x4e, 0xdb, 0x49, 0xae, 0xd6, 0x36, 0x90, 0x21, 0x6c,
            0xc2, 0x72, 0x8d, 0xc5, 0x8f, 0x55, 0x23, 0x78, 0xc2, 0x92, 0xab, 0x58, 0x44, 0xf3,
        ]
    );
}

#[derive(Debug, Clone)]
pub struct Field(BigInt);

impl Field {
    pub fn new(value: BigInt) -> Self {
        if value < BigInt::zero() {
            Self((&p as &BigInt) + value)
        } else {
            Self(value % &p as &BigInt)
        }
    }

    /// Field inverse (inverse of 0 is 0).
    pub fn inv(self) -> Self {
        Self::new(self.0.modpow(&(&p as &BigInt - 2), &p))
    }

    /// Compute sign of number, 0 or 1.  The sign function
    /// has the following property:
    /// sign(x) = 1 - sign(-x) if x != 0.
    pub fn sign(&self) -> BigInt {
        &self.0 % 2
    }

    /// Field square root.  Returns none if square root does not exist.
    /// Note: not presently implemented for p mod 8 = 1 case.
    pub fn sqrt(self) -> crate::Result<Field> {
        // Compute candidate square root.
        let y = self
            .0
            .modpow(&((&p as &BigInt).add(1_u32).div(&4)), &p as &BigInt);
        let y = Field::new(y);
        // Check square root candidate valid.
        if &y * &y == self {
            Ok(y)
        } else {
            Err(Ed448Error::InvalidPoint)
        }
    }

    /// Is the field element the additive identity?
    pub fn is_zero(&self) -> bool {
        self.0 == BigInt::zero()
    }
}

impl PartialEq for Field {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Add for Field {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        self + &other
    }
}

impl Add<&'_ Field> for Field {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self {
        Self::new(self.0 + &rhs.0)
    }
}

impl Add<&'_ Field> for &'_ Field {
    type Output = Field;

    fn add(self, other: &Field) -> Self::Output {
        self.clone() + other
    }
}

impl Sub for Field {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self - &other
    }
}

impl Sub<&'_ Field> for Field {
    type Output = Self;

    fn sub(self, other: &Self) -> Self {
        Self::new(self.0 + &p as &BigInt - &other.0)
    }
}

impl Sub<&'_ Field> for &'_ Field {
    type Output = Field;

    fn sub(self, other: &Field) -> Field {
        self.clone() - other
    }
}

impl Mul for Field {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        self * &other
    }
}

impl Mul<&'_ Field> for Field {
    type Output = Self;

    fn mul(self, other: &Self) -> Self {
        Self::new(self.0 * &other.0)
    }
}

impl Mul<&'_ Field> for &'_ Field {
    type Output = Field;

    fn mul(self, other: &Field) -> Field {
        self.clone() * other
    }
}

impl Neg for Field {
    type Output = Self;

    fn neg(self) -> Self {
        Self::new(&p as &BigInt - self.0)
    }
}

impl Div for Field {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        self / &other
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div<&'_ Field> for Field {
    type Output = Self;

    fn div(self, other: &Self) -> Self {
        self * other.clone().inv()
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("Field {{ {} }}", self.0))
    }
}

#[derive(Debug, Clone)]
pub struct Point {
    x: Field,
    y: Field,
    z: Field,
}

impl Point {
    pub fn new(x: &Field, y: &Field) -> crate::Result<Self> {
        // Check that the point is actually on the curve.
        if y * y + x * x != (&f1 as &Field) + &((&d as &Field) * x * x * y * y) {
            Err(Ed448Error::InvalidPoint)
        } else {
            Ok(Self {
                x: x.clone(),
                y: y.clone(),
                ..Default::default()
            })
        }
    }

    /// Order of basepoint.
    pub fn l() -> &'static BigInt {
        &l as &BigInt
    }

    pub fn new_stdbase() -> Self {
        Self::new(&f0, &f1).unwrap()
    }

    /// Point doubling.
    pub fn double(self) -> Self {
        // The formulas are from EFD.
        let (x1s, y1s, z1s) = (&self.x * &self.x, &self.y * &self.y, &self.z * &self.z);
        let xys = &self.x + &self.y;
        let F = &x1s + &y1s;
        let J = &F - &(&z1s + &z1s);
        let (x, y, z) = (
            (&xys * &xys - &x1s - &y1s) * &J,
            &F * &(&x1s - &y1s),
            &F * &J,
        );

        Self { x, y, z }
    }

    /// Encode a point representation.
    pub fn encode(self) -> [u8; KEY_LENGTH] {
        let (xp, yp) = (self.x / &self.z, self.y / self.z);

        // Encode y.
        let mut tmp = yp.0.magnitude().to_bytes_le();
        tmp.resize_with(KEY_LENGTH, Default::default);
        let mut s = array_to_key(&tmp);

        // Add sign bit of x to encoding.
        if !xp.sign().is_zero() {
            s[56] |= 0b1000_0000;
        }
        s
    }

    /// Decode a point representation.
    pub fn decode(self, s: &[u8]) -> crate::Result<Point> {
        // Check that point encoding is the correct length.
        if s.len() != KEY_LENGTH {
            return Err(Ed448Error::WrongEncodedPointLength);
        }
        // Extract signbit.
        let xs = BigInt::from(s[56] >> 7);
        // Decode y.  If this fails, fail.
        let y = self.frombytes(s)?;
        // Try to recover x.  If it does not exist, or if zero and xs
        // are wrong, fail.
        let mut x = self.solve_x2(&y).sqrt()?;
        if x.is_zero() && xs != x.sign() {
            return Err(Ed448Error::InvalidPoint);
        }
        // If sign of x isn't correct, flip it.
        if x.sign() != xs {
            x = -x;
        }
        // Return the constructed point.
        Point::new(&x, &y)
    }

    /// Unserialize number from bits.
    fn frombytes(&self, x: &[u8]) -> crate::Result<Field> {
        let rv = BigInt::from_bytes_le(Sign::Plus, x) % BigInt::from(2).pow(455);
        if &rv < &p as &BigInt {
            Ok(Field::new(rv))
        } else {
            Err(Ed448Error::InvalidPoint)
        }
    }

    /// Solve for x^2.
    fn solve_x2(self, y: &Field) -> Field {
        (y * y - &f1 as &Field) / (&d as &Field * y * y - &f1 as &Field)
    }
}

impl Mul<&'_ BigInt> for Point {
    type Output = Self;

    fn mul(self, x: &BigInt) -> Self {
        self * x.clone()
    }
}

impl Mul<BigInt> for Point {
    type Output = Self;

    fn mul(mut self, mut x: BigInt) -> Self {
        let mut r = Point::new_stdbase();
        let mut _r = r.to_string();
        let mut _x = x.to_string();
        while !x.is_zero() {
            if !((&x % 2) as BigInt).is_zero() {
                r = r + &self;
            }
            self = self.double();
            x /= 2;
            _r = r.to_string();
            _x = x.to_string();
        }
        r
    }
}

impl Add for Point {
    type Output = Self;

    fn add(self, y: Self) -> Self {
        // The formulas are from EFD.
        let (xcp, ycp, zcp) = (&self.x * &y.x, &self.y * &y.y, &self.z * &y.z);
        let B = &zcp * &zcp;
        let E = &d as &Field * &xcp * &ycp;
        let (F, G) = (&B - &E, B + E);

        let x = &zcp * &F * ((self.x + self.y) * (y.x + y.y) - &xcp - &ycp);
        let (y, z) = (zcp * &G * (ycp - xcp), F * G);

        Self { x, y, z }
    }
}

impl Add<&'_ Point> for Point {
    type Output = Self;

    fn add(self, other: &Point) -> Self {
        self + other.clone()
    }
}

impl Add<&'_ Point> for &'_ Point {
    type Output = Point;

    fn add(self, other: &Point) -> Point {
        self.clone() + other.clone()
    }
}

impl PartialEq<Point> for Point {
    fn eq(&self, other: &Point) -> bool {
        // Need to check x1/z1 == x2/z2 and similarly for y, so cross
        // multiply to eliminate divisions.
        let xn1 = &self.x * &other.z;
        let xn2 = &other.x * &self.z;
        let yn1 = &self.y * &other.z;
        let yn2 = &other.y * &self.z;
        xn1 == xn2 && yn1 == yn2
    }
}

impl Default for Point {
    fn default() -> Self {
        Self {
            x: xb.clone(),
            y: yb.clone(),
            z: Field::new(BigInt::one()),
        }
    }
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!(
            "Point {{ x: {}, y: {}, z: {} }}",
            self.x, self.y, self.z
        ))
    }
}