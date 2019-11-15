using System;
using Neuralia.Blockchains.Tools.Data;
using Neuralia.Blockchains.Tools.Data.Arrays;
using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.pqc.math.linearalgebra {

	/// <summary>
	///     This class implements permutations of the set {0,1,...,n-1} for some given n
	///     &gt; 0, i.e., ordered sequences containing each number <tt>m</tt> (
	///     <tt>
	///         0 &lt;=
	///         m &lt; n
	///     </tt>
	///     )
	///     once and only once.
	/// </summary>
	public class Permutation {

		/// <summary>
		///     perm holds the elements of the permutation vector, i.e.
		///     <tt>
		///         [perm(0),
		///         perm(1), ..., perm(n-1)]
		///     </tt>
		/// </summary>
		private readonly int[] perm;

		/// <summary>
		///     Create the identity permutation of the given size.
		/// </summary>
		/// <param name="n"> the size of the permutation </param>
		public Permutation(int n) {
			if(n <= 0) {
				throw new ArgumentException("invalid length");
			}

			this.perm = new int[n];

			for(int i = n - 1; i >= 0; i--) {
				this.perm[i] = i;
			}
		}

		/// <summary>
		///     Create a permutation using the given permutation vector.
		/// </summary>
		/// <param name="perm"> the permutation vector </param>
		public Permutation(int[] perm) {
			if(!this.isPermutation(perm)) {
				throw new ArgumentException("array is not a permutation vector");
			}

			this.perm = IntUtils.clone(perm);
		}

		/// <summary>
		///     Create a permutation from an encoded permutation.
		/// </summary>
		/// <param name="enc"> the encoded permutation </param>
		public Permutation(SafeArrayHandle enc) {
			if(enc.Length <= 4) {
				throw new ArgumentException("invalid encoding");
			}

			int n    = LittleEndianConversions.OS2IP(enc, 0);
			int size = IntegerFunctions.ceilLog256(n - 1);

			if(enc.Length != (4 + (n * size))) {
				throw new ArgumentException("invalid encoding");
			}

			this.perm = new int[n];

			for(int i = 0; i < n; i++) {
				this.perm[i] = LittleEndianConversions.OS2IP(enc, 4 + (i * size), size);
			}

			if(!this.isPermutation(this.perm)) {
				throw new ArgumentException("invalid encoding");
			}

		}

		/// <summary>
		///     Create a random permutation of the given size.
		/// </summary>
		/// <param name="n">  the size of the permutation </param>
		/// <param name="sr"> the source of randomness </param>
		public Permutation(int n, SecureRandom sr) {
			if(n <= 0) {
				throw new ArgumentException("invalid length");
			}

			this.perm = new int[n];

			int[] help = new int[n];

			for(int i = 0; i < n; i++) {
				help[i] = i;
			}

			int k = n;

			for(int j = 0; j < n; j++) {
				int i = RandUtils.nextInt(sr, k);
				k--;
				this.perm[j] = help[i];
				help[i]      = help[k];
			}
		}

		/// <summary>
		///     Encode this permutation as byte array.
		/// </summary>
		/// <returns> the encoded permutation </returns>
		public virtual SafeArrayHandle Encoded {
			get {
				int         n      = this.perm.Length;
				int         size   = IntegerFunctions.ceilLog256(n                    - 1);
				SafeArrayHandle result = ByteArray.Create(4 + (n * size));
				LittleEndianConversions.I2OSP(n, result, 0);

				for(int i = 0; i < n; i++) {
					LittleEndianConversions.I2OSP(this.perm[i], result, 4 + (i * size), size);
				}

				return result;
			}
		}

		/// <returns> the permutation vector <tt>(perm(0),perm(1),...,perm(n-1))</tt> </returns>
		public virtual int[] Vector => IntUtils.clone(this.perm);

		/// <summary>
		///     Compute the inverse permutation <tt>P<sup>-1</sup></tt>.
		/// </summary>
		/// <returns>
		///     <tt>this<sup>-1</sup></tt>
		/// </returns>
		public virtual Permutation computeInverse() {
			Permutation result = new Permutation(this.perm.Length);

			for(int i = this.perm.Length - 1; i >= 0; i--) {
				result.perm[this.perm[i]] = i;
			}

			return result;
		}

		/// <summary>
		///     Compute the product of this permutation and another permutation.
		/// </summary>
		/// <param name="p"> the other permutation </param>
		/// <returns>
		///     <tt>this * p</tt>
		/// </returns>
		public virtual Permutation rightMultiply(Permutation p) {
			if(p.perm.Length != this.perm.Length) {
				throw new ArgumentException("length mismatch");
			}

			Permutation result = new Permutation(this.perm.Length);

			for(int i = this.perm.Length - 1; i >= 0; i--) {
				result.perm[i] = this.perm[p.perm[i]];
			}

			return result;
		}

		/// <summary>
		///     checks if given object is equal to this permutation.
		///     <para>
		///         The method returns false whenever the given object is not permutation.
		///     </para>
		/// </summary>
		/// <param name="other">
		///     -
		///     permutation
		/// </param>
		/// <returns> true or false </returns>
		public override bool Equals(object other) {

			if(!(other is Permutation)) {
				return false;
			}

			Permutation otherPerm = (Permutation) other;

			return IntUtils.Equals(this.perm, otherPerm.perm);
		}

		/// <returns> a human readable form of the permutation </returns>
		public override string ToString() {
			string result = "[" + this.perm[0];

			for(int i = 1; i < this.perm.Length; i++) {
				result += ", " + this.perm[i];
			}

			result += "]";

			return result;
		}

		/// <returns> the hash code of this permutation </returns>
		public override int GetHashCode() {
			return this.perm.GetHashCode();
		}

		/// <summary>
		///     Check that the given array corresponds to a permutation of the set
		///     <tt>{0, 1, ..., n-1}</tt>.
		/// </summary>
		/// <param name="perm"> permutation vector </param>
		/// <returns> true if perm represents an n-permutation and false otherwise </returns>
		private bool isPermutation(int[] perm) {
			int    n        = perm.Length;
			bool[] onlyOnce = new bool[n];

			for(int i = 0; i < n; i++) {
				if((perm[i] < 0) || (perm[i] >= n) || onlyOnce[perm[i]]) {
					return false;
				}

				onlyOnce[perm[i]] = true;
			}

			return true;
		}
	}

}