#[derive(Debug, Eq, PartialEq, Clone, Copy)]
/// Defines wether a claim is validated or not
pub enum Validation<T> {
    /// This field is not validated
    Ignored,

    /// This field is validated using the value T
    Validate(T)
}

// This doesn't compile currently
//impl<T> Debug for Validation<T> where T: ?Debug {
//    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), Error> {
//        match self {
//            Validation::Ignored => write!(f, "Ignored"),
//            Validation::Validate(_) => write!(f, "Validate")
//        }
//    }
//}



impl<T> Default for Validation<T> {
    fn default() -> Self {
        Validation::Ignored
    }
}

impl<T> Validation<T> {
    /// Map the value to another validation requirement, similar to how .map works on iter()
    pub fn map<U, F>(self, f: F) -> Validation<U> where F: FnOnce(T) -> U {
        match self {
            Validation::Ignored => Validation::Ignored,
            Validation::Validate(t) => Validation::Validate(f(t))
        }
    }
}
