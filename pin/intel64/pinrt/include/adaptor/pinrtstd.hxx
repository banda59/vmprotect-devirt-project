/*
 * Copyright (C) 2022-2025 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

// <COMPONENT>: pinrt
// <FILE-TYPE>: implementation

#ifndef _PINRTSTD_H_
#define _PINRTSTD_H_

#include <stddef.h>
#include <stdint.h>

namespace pinrt
{
namespace std
{

template< class T, T __v > struct integral_constant
{
    static constexpr const T value = __v;
    typedef T value_type;
    typedef integral_constant type;
    inline constexpr operator value_type() const noexcept { return value; }
    inline constexpr value_type operator()() const noexcept { return value; }
};
template< bool __b > using bool_constant = integral_constant< bool, __b >;

using false_type = bool_constant< false >;
using true_type  = bool_constant< true >;

template< class T, class U > struct is_same : public false_type
{
};

template< class T > struct is_same< T, T > : public true_type
{
};

template< class T > struct is_lvalue_reference : public false_type
{
};
template< class T > struct is_lvalue_reference< T& > : public true_type
{
};
template< class _Tp > struct is_rvalue_reference : public false_type
{
};
template< class _Tp > struct is_rvalue_reference< _Tp&& > : public true_type
{
};

template< bool B, class T = void > struct enable_if
{
};

template< class T > struct enable_if< true, T >
{
    typedef T type;
};

template< bool B, class T = void > using enable_if_t = typename enable_if< B, T >::type;

template< class T > struct remove_reference
{
    typedef T type;
};
template< class T > struct remove_reference< T& >
{
    typedef T type;
};
template< class T > struct remove_reference< T&& >
{
    typedef T type;
};

template< class T > inline constexpr typename remove_reference< T >::type&& move(T&& __t) noexcept
{
    typedef typename remove_reference< T >::type _Up;
    return static_cast< _Up&& >(__t);
}

template< class T > inline constexpr T&& forward(typename remove_reference< T >::type& __t) noexcept
{
    return static_cast< T&& >(__t);
}

template< class T > inline constexpr T&& forward(typename remove_reference< T >::type&& __t) noexcept
{
    static_assert(!is_lvalue_reference< T >::value, "Can not forward an rvalue as an lvalue");
    return static_cast< T&& >(__t);
}

// remove_const

template< class _Tp > struct remove_const
{
    typedef _Tp type;
};
template< class _Tp > struct remove_const< const _Tp >
{
    typedef _Tp type;
};
template< class _Tp > using remove_const_t = typename remove_const< _Tp >::type;

// remove_volatile

template< class _Tp > struct remove_volatile
{
    typedef _Tp type;
};
template< class _Tp > struct remove_volatile< volatile _Tp >
{
    typedef _Tp type;
};
template< class _Tp > using remove_volatile_t = typename remove_volatile< _Tp >::type;

// remove_cv

template< class _Tp > struct remove_cv
{
    typedef typename remove_volatile< typename remove_const< _Tp >::type >::type type;
};
template< class _Tp > using remove_cv_t = typename remove_cv< _Tp >::type;

template< class _Tp > struct simple_decay
{
    using type = remove_cv_t< typename remove_reference< _Tp >::type >;
};

template< class T > using simple_decay_t = typename simple_decay< T >::type;

template< class _Tp > struct remove_pointer
{
    typedef _Tp type;
};
template< class _Tp > struct remove_pointer< _Tp* >
{
    typedef _Tp type;
};
template< class _Tp > struct remove_pointer< _Tp* const >
{
    typedef _Tp type;
};
template< class _Tp > struct remove_pointer< _Tp* volatile >
{
    typedef _Tp type;
};
template< class _Tp > struct remove_pointer< _Tp* const volatile >
{
    typedef _Tp type;
};
template< class _Tp > using remove_pointer_t = typename remove_pointer< _Tp >::type;

template< typename > struct __is_integral_helper : public false_type
{
};

template<> struct __is_integral_helper< bool > : public true_type
{
};

template<> struct __is_integral_helper< char > : public true_type
{
};

template<> struct __is_integral_helper< signed char > : public true_type
{
};

template<> struct __is_integral_helper< unsigned char > : public true_type
{
};

template<> struct __is_integral_helper< wchar_t > : public true_type
{
};

template<> struct __is_integral_helper< char16_t > : public true_type
{
};

template<> struct __is_integral_helper< char32_t > : public true_type
{
};

template<> struct __is_integral_helper< short > : public true_type
{
};

template<> struct __is_integral_helper< unsigned short > : public true_type
{
};

template<> struct __is_integral_helper< int > : public true_type
{
};

template<> struct __is_integral_helper< unsigned int > : public true_type
{
};

template<> struct __is_integral_helper< long > : public true_type
{
};

template<> struct __is_integral_helper< unsigned long > : public true_type
{
};

template<> struct __is_integral_helper< long long > : public true_type
{
};

template<> struct __is_integral_helper< unsigned long long > : public true_type
{
};

/// @cond undocumented
template< typename > struct __is_floating_point_helper : public false_type
{
};

template<> struct __is_floating_point_helper< float > : public true_type
{
};

template<> struct __is_floating_point_helper< double > : public true_type
{
};

template<> struct __is_floating_point_helper< long double > : public true_type
{
};

/// is_integral
template< typename _Tp > struct is_integral : public __is_integral_helper< remove_cv_t< _Tp > >::type
{
};

/// is_floating_point
template< typename _Tp > struct is_floating_point : public __is_floating_point_helper< remove_cv_t< _Tp > >::type
{
};

template< class T > struct is_pointer : public false_type
{
};

template< class T > struct is_pointer< T* > : public true_type
{
};

template< class T > struct is_pointer< T* const > : public true_type
{
};

template< class T > struct is_pointer< T* volatile > : public true_type
{
};

template< class T > struct is_pointer< T* const volatile > : public true_type
{
};

/**
 * @brief s a CopyConstructible and CopyAssignable wrapper around a reference to object 
 * 
 * This is a simplified version of std::reference_wrapper and is not designed
 * to wrap callable objects
 * 
 * @tparam _Tp 
 */
template< class _Tp > class simple_reference_wrapper
{
  public:
    // types
    typedef _Tp type;

  private:
    type* __f_;

  public:
    // construct/copy/destroy
    constexpr simple_reference_wrapper(type& __f) noexcept : __f_(&__f) {}

    simple_reference_wrapper(type&&) = delete; // do not bind to temps

    // access
    constexpr operator type&() const noexcept { return *__f_; }
    constexpr type& get() const noexcept { return *__f_; }
};

template< class _Tp > inline constexpr simple_reference_wrapper< _Tp > ref(_Tp& __t) noexcept
{
    return simple_reference_wrapper< _Tp >(__t);
}

template< class _Tp > inline constexpr simple_reference_wrapper< _Tp > ref(simple_reference_wrapper< _Tp > __t) noexcept
{
    return ref(__t.get());
}

template< class _Tp > inline constexpr simple_reference_wrapper< const _Tp > cref(const _Tp& __t) noexcept
{
    return simple_reference_wrapper< const _Tp >(__t);
}

template< class _Tp > inline constexpr simple_reference_wrapper< const _Tp > cref(simple_reference_wrapper< _Tp > __t) noexcept
{
    return cref(__t.get());
}

template< typename T, typename U > inline constexpr T safe_int_cast(U ii) noexcept
{
    static_assert(is_integral< U >::value, "Source type must be integral");
    static_assert(sizeof(T) >= sizeof(U), "Cast will loose data!");
    if constexpr (is_integral< T >::value)
    {
        return static_cast< T >(ii);
    }
    else
    {
        return reinterpret_cast< T >(ii);
    }
}

template< typename T, typename U > inline constexpr T safe_pointer_cast(U* p) noexcept
{
    static_assert(sizeof(T) >= sizeof(p), "Cast will loose data!");
    return reinterpret_cast< T >(p);
}

template< typename T, typename U > inline constexpr T safe_pointer_cast(U const* p) noexcept
{
    static_assert(sizeof(T) >= sizeof(p), "Cast will loose data!");
    return reinterpret_cast< T >(const_cast< U* >(p));
}

template< typename T, typename U > inline constexpr T unsafe_pointer_cast(U* p) noexcept
{
    return static_cast< T >(reinterpret_cast< uintptr_t >(p));
}

template< typename T, typename U > inline constexpr T unsafe_pointer_cast(U const* p) noexcept
{
    return static_cast< T >(reinterpret_cast< uintptr_t >(const_cast< U* >(p)));
}

// TODO(eonne): Find a way to introduce C++20 bitcast
// template<class To, class From>
// cxx::enable_if_t<sizeof(To) == sizeof(From), To> bit_cast(const From& src) noexcept
// {
//     // TODO(eonne): Add conditions to above SFINAE for both types to be is_trivially_copyable
//     // TODO(eonne): Add static assert for is_trivially_constructible
//     To dst;
//     std::memcpy(&dst, &src, sizeof(To));
//     return dst;
// }

/**
 * @brief This utility class allows adding code fragments that will be called when the
 *        class goes out of scope
 * 
 *      Trying to add more fragments than specified will not trigger an error but
 *      the extra fragments will be silently dropped and will not be executed
 *      Trying to pass a Callable with size greater than MAX_CALLABLE_SIZE will trigger 
 *      a compilation time assertion
 * 
 * @tparam MAX_FRAGMENTS The maximum number of fragments allowed
 * @tparam MAX_CALLABLE_SIZE The maximum size of a callable object
 * 
 * When using scoped_finalizer as a transactional finalizer, the user can choose
 * to register specific code fragments to be executed on rollback and on commit.
 * By default when adding a fragment it will be called when the finalizer goes out of scope.
 * It's possible for telling the finalizer to register the next fragment as either rollback fragment
 * or commit fragment by calling rollback_mod or commit_mod before adding the fragment.
 * Once a fragment is added the mod is reset to the default.
 * 
 * To execute the rollback fragments  one has to call rollback() and to execute the commit fragments one
 * has to call commit(). Calling rollback(), invalidates all executed fragments as well as all commit fragments.
 * Calling commit(), invalidates all executed fragments as well as all rollback fragments.
 * This way calling roolback() or commit() twice will not execute the fragments twice.
 * Also calling rollback() after commit(), or commit() after rollback() will have no effect.
 * The proper way to handle rollback() & commit() is to call them once just before the scope exits.
 * If this is a function one can directly call return on commit() or rollback() (See below)
 * 
 * Fragments are always executed in reverse insertion order
 * 
 * Usage:
 * declare the finalizer at the begining of the scope
 * {
 *      scoped_finalizer f_;
 * 
 *      // Adding code fragments that will be executed at the end of scope
 *      // This is the default and will always be executed also on rollback & commit
 *      f_ += []() {
 *          // F0: Some code to run at the end of scope
 *      };
 * 
 *      // Adding fragments that will be executed on rollback
 *      f_.rollback_mod() += []() {
 *          // R0: Some code that will run on call to f_.rollback()
 *      }
 * 
 *      // Adding fragments that will be executed on commit
 *      f_.commit_mod() += []() {
 *          // C0: Some code that will run on call to f_.commit()
 *      }
 * 
 *      if(someerror)
 *      {
 *          return f_.rollback(retValue);
 *          // Clenup order:
 *          // R0
 *          // F0
 *      }
 * 
 *      // Success - commit transaction
 *      return f_.commit(retValue);
 *      // Cleanu order:
 *      // C0
 *      // F0
 * 
 * }
 * 
 */
template< unsigned MAX_FRAGMENTS = 64U, unsigned MAX_CALLABLE_SIZE = 64U > class scoped_finalizer
{
  private:
    enum class e_tag
    {
        finalizer,
        commit,
        rollback,
        deleted
    };
    struct bindable
    {
        virtual ~bindable() noexcept   = default;
        virtual void invoke() noexcept = 0;

        static void* operator new(size_t, void* __p) noexcept { return __p; }
        static void operator delete(void*, size_t) noexcept
        {
            // Do nothing
        }
    };
    template< class Callable > struct callable final : bindable
    {
        Callable c_;
        void invoke() noexcept override { c_(); }

        callable(Callable&& c) noexcept : c_(move(c)) {}
        ~callable() = default;
    };
    alignas(MAX_CALLABLE_SIZE) unsigned char scratch_[MAX_CALLABLE_SIZE * MAX_FRAGMENTS];
    e_tag fragmentTags_[MAX_FRAGMENTS];
    bindable* fragments_[MAX_FRAGMENTS] = {0};
    unsigned freeLoc_                   = 0U;
    unsigned fcount_                    = 0U;
    e_tag nextTag_                      = e_tag::finalizer;

  public:
    scoped_finalizer()                                   = default;
    scoped_finalizer(const scoped_finalizer&)            = delete;
    scoped_finalizer(scoped_finalizer&&)                 = delete;
    scoped_finalizer& operator=(const scoped_finalizer&) = delete;
    scoped_finalizer& operator=(scoped_finalizer&&)      = delete;

    /**
     * @brief Add a callable code fragment to the end of the fragment list.
     *        The fragment mod is always reset to the default after the fragment is added
     * 
     *      If the number of added fragments reached MAX_FRAGMENTS any additional
     *      fragments will be silently ignored
     * 
     *      After the fragment is added the mod is reset /see rollback_mod, /see commit_mod
     * 
     * @tparam Callable 
     * @param fragment The code fragment
     * @return scoped_finalizer& 
     */
    template< class Callable > scoped_finalizer& operator+=(Callable&& fragment) noexcept
    {
        static_assert(sizeof(callable< Callable >) <= MAX_CALLABLE_SIZE, "Callable is too big for us");
        if (fcount_ < MAX_FRAGMENTS)
        {
            fragmentTags_[fcount_] = nextTag_;
            fragments_[fcount_++]  = new ((void*)&scratch_[freeLoc_]) callable< Callable >(forward< Callable >(fragment));

            // Make sure next callable is added at a MAX_CALLABLE_SIZE boundary for proper memory alignment
            freeLoc_ += MAX_CALLABLE_SIZE;
        }
        else
        {
            __asm__ __volatile__("hlt" : : : "memory"); // Crash & Burn
        }
        nextTag_ = e_tag::finalizer;
        return *this;
    }

    /**
     * @brief Change the mod for the next fragment to rollback
     * 
     * @return A refernece to *this 
     */
    scoped_finalizer& rollback_mod() noexcept
    {
        nextTag_ = e_tag::rollback;
        return *this;
    }

    /**
     * @brief Change the mod for the next fragment to commit
     * 
     * @return A refernece to *this 
     */
    scoped_finalizer& commit_mod() noexcept
    {
        nextTag_ = e_tag::commit;
        return *this;
    }

    /**
     * @brief Execute rollback fragments and return the supllied return value
     * 
     * All executed fragments will be invalidated as well as all commit fragments
     * 
     * @tparam RetType The type of the return value
     * @param r         The return value 
     * @return r
     */
    template< typename RetType > RetType rollback(RetType r) noexcept
    {
        for (int i = int(fcount_) - 1; i >= 0; --i)
        {
            switch (fragmentTags_[i])
            {
                case e_tag::commit:
                    // Make sure commit fragment is not executed after rollback
                    fragmentTags_[i] = e_tag::deleted;
                    break;
                case e_tag::rollback:
                    fragments_[i]->invoke();
                    // Prevent double execution
                    fragmentTags_[i] = e_tag::deleted;
                    break;
                default:
                    break;
            }
        }
        return r;
    }

    /**
     * @brief Execute commit fragments and return the supllied return value
     * 
     * All executed fragments will be invalidated as well as all rollback fragments

     * @tparam RetType The type of the return value
     * @param r         The return value 
     * @return r
     */
    template< typename RetType > RetType commit(RetType r) noexcept
    {
        for (int i = int(fcount_) - 1; i >= 0; --i)
        {
            switch (fragmentTags_[i])
            {
                case e_tag::commit:
                    fragments_[i]->invoke();
                    // Prevent double execution
                    fragmentTags_[i] = e_tag::deleted;
                    break;
                case e_tag::rollback:
                    // Make sure rollback fragment is not executed after commit
                    fragmentTags_[i] = e_tag::deleted;
                    break;
                default:
                    break;
            }
        }
        return r;
    }

    ~scoped_finalizer()
    {
        // For good measure we cleanup in reverse order
        for (int i = int(fcount_) - 1; i >= 0; --i)
        {
            if (e_tag::finalizer == fragmentTags_[i])
            {
                fragments_[i]->invoke();
            }
            delete fragments_[i];
        }
    }
};

/**
 * @brief A simple class that allows applying a deleter to a value at the end of scope.
 *        This class can be used as a poor's man unique_ptr
 * 
 * @tparam T                The type of the value stored by the class
 * @tparam Deleter          The type of the deleter to be applied to the value when the
 *                          class goes out of scope. The deleter must be a callable that
 *                          accepts one argument of type T&&
 * An example of a NOP delter (a deleter that does nothing)
 * template< typename T > struct nop_deleter
 * {
 *   void operator()(T&&) {}
 * };
 * 
 * A possible usage can be:
 * simple_scoped_value<int, nop_deleter<int>> scopedInt {0};
 * 
 * Another option:
 * simple_scoped_value<int, void(*)(int&&)> scopedInt {0, [](int&& v) {
 *      // Do something with v
 * }};
 */
template< typename T, class Deleter > class simple_scoped_value
{
    static_assert(!is_rvalue_reference< Deleter >::value, "the specified deleter type cannot be an rvalue reference");

  public:
    simple_scoped_value() noexcept : val_{}, owner_(false) {}
    template< typename U = Deleter, class = enable_if_t< is_lvalue_reference< U >::value, Deleter > >
    simple_scoped_value(T&& val, typename remove_reference< U >::type const& d) noexcept : val_(val), owner_(true), deleter_(d)
    {}
    template< typename U = Deleter, class = enable_if_t< !is_lvalue_reference< U >::value, Deleter > >
    simple_scoped_value(T&& val, U&& d) noexcept : val_(val), owner_(true), deleter_(forward< Deleter >(d))
    {}
    simple_scoped_value(T&& val) noexcept : val_(val), owner_(true) {}
    template< class U > simple_scoped_value(simple_scoped_value< T, U >&) = delete;
    template< class U >
    simple_scoped_value(simple_scoped_value< T, U >&& o) : owner_(false) // Must be initialized to false before call to reset
    {
        o.owner_ = false;
        reset(move(o.val_));
    }
    ~simple_scoped_value() { reset(); }

    template< class U > simple_scoped_value& operator=(simple_scoped_value< T, U > const&) = delete;
    template< class U > simple_scoped_value& operator=(simple_scoped_value< T, U >&& o) noexcept
    {
        o.owner_ = false;
        reset(move(o.val_));
        return *this;
    }
    simple_scoped_value& operator=(T&& v) noexcept
    {
        reset(forward< T >(v));
        return *this;
    }

    bool operator!=(simple_scoped_value const& o) noexcept
    {
        if (owner_ && o.owner_)
        {
            return val_ != o.val_;
        }
        return true; // If we are not the owners we are always not equal
    }

    bool operator==(simple_scoped_value const& o) noexcept { return !this->operator!=(o); }

    void reset() noexcept
    {
        if (owner_)
        {
            deleter_(move(val_));
            owner_ = false;
        }
    }

    void reset(T&& v) noexcept
    {
        reset();
        val_   = move(v);
        owner_ = true;
    }

    T release() noexcept
    {
        owner_ = false;
        return val_;
    }

    bool valid() const noexcept { return owner_; }

    T& get() const noexcept { return val_; }
    T& get() noexcept { return val_; }

    T& operator->() const noexcept { return val_; }
    T& operator->() noexcept { return val_; }

  private:
    T val_;
    bool owner_;
    Deleter deleter_;
};

/**
 * @brief Returns upper-bound for number of digits in integer of given type
 * 
 * @tparam T The type of integer
 * 
 * @note We want to find the number of digits in base 10 which is ceil(log10(INT_MAX))
 */
template< typename T > constexpr size_t decimal_digits_ubound()
{
    // Number of digits calculated by using some convenient log base of 256.
    // Explanation by example on 4-bytes integer -- applies to all sizes:
    // We want to find the number of digits in base 10 which is ceil(log10(INT_MAX))
    //           | NumberOfDigits = floor(log10(INT_MAX)) + 1
    //        => | NumberOfDigits = floor(log256(INT_MAX) / log256(10)) + 1
    // Provided: | log256(INT_MAX) = 3.875
    // Provided: | 1 / log256(10) = ~2.40824
    //        => | NumberOfDigits <= floor(sizeof(int) * 2.40824) + 1
    // Provided: | ~2.40824 = ~2.41 = ~241 / 100;
    //        => | NumberOfDigits = 241 * sizeof(int) / 100 + 1
    return 241 * sizeof(T) / 100 + 1;
}
} // namespace std

} // namespace pinrt

#endif // _PINRTSTD_H_
