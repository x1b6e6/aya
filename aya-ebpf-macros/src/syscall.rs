use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{ItemFn, Result};

pub struct Syscall {
    item: ItemFn,
}

impl Syscall {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        if !attrs.is_empty() {
            abort!(attrs, "unexpected attribute")
        }

        let item: ItemFn = syn::parse2(item)?;

        Ok(Self { item })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let item = &self.item;
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;

        Ok(quote! {
            #[no_mangle]
            #[link_section = "syscall"]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i64 {
                return  #fn_name(::aya_ebpf::programs::SyscallContext::new(ctx));

                #[inline(always)]
                #item
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use super::*;

    #[test]
    fn test_syscall() {
        let prog = Syscall::parse(
            parse_quote! {},
            parse_quote! {
                fn prog(ctx: ::aya_ebpf::programs::SyscallContext) -> i64 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "syscall"]
            fn prog(ctx: *mut ::core::ffi::c_void) -> i64 {
                return prog(::aya_ebpf::programs::SyscallContext::new(ctx));

                #[inline(always)]
                fn prog(ctx: ::aya_ebpf::programs::SyscallContext) -> i64 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
