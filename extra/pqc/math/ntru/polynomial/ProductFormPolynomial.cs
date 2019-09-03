using System.IO;
using Neuralia.Blockchains.Tools.Data;
using Org.BouncyCastle.Security;

namespace Neuralia.BouncyCastle.extra.pqc.math.ntru.polynomial {

	/// <summary>
	///     A polynomial of the form <code>f1*f2+f3</code>, where
	///     <code>f1,f2,f3</code> are very sparsely populated ternary polynomials.
	/// </summary>
	public class ProductFormPolynomial : IPolynomial {
		private readonly SparseTernaryPolynomial f1;
		private readonly SparseTernaryPolynomial f2;
		private readonly SparseTernaryPolynomial f3;

		public ProductFormPolynomial(SparseTernaryPolynomial f1, SparseTernaryPolynomial f2, SparseTernaryPolynomial f3) {
			this.f1 = f1;
			this.f2 = f2;
			this.f3 = f3;
		}

		public virtual IntegerPolynomial mult(IntegerPolynomial b) {
			IntegerPolynomial c = this.f1.mult(b);
			c = this.f2.mult(c);
			c.add(this.f3.mult(b));

			return c;
		}

		public virtual BigIntPolynomial mult(BigIntPolynomial b) {
			BigIntPolynomial c = this.f1.mult(b);
			c = this.f2.mult(c);
			c.add(this.f3.mult(b));

			return c;
		}

		public virtual IntegerPolynomial toIntegerPolynomial() {
			IntegerPolynomial i = this.f1.mult(this.f2.toIntegerPolynomial());
			i.add(this.f3.toIntegerPolynomial());

			return i;
		}

		public virtual IntegerPolynomial mult(IntegerPolynomial poly2, int modulus) {
			IntegerPolynomial c = this.mult(poly2);
			c.mod(modulus);

			return c;
		}

		public static ProductFormPolynomial generateRandom(int N, int df1, int df2, int df3Ones, int df3NegOnes, SecureRandom random) {
			SparseTernaryPolynomial f1 = SparseTernaryPolynomial.generateRandom(N, df1, df1, random);
			SparseTernaryPolynomial f2 = SparseTernaryPolynomial.generateRandom(N, df2, df2, random);
			SparseTernaryPolynomial f3 = SparseTernaryPolynomial.generateRandom(N, df3Ones, df3NegOnes, random);

			return new ProductFormPolynomial(f1, f2, f3);
		}

		public static ProductFormPolynomial fromBinary(IByteArray data, int N, int df1, int df2, int df3Ones, int df3NegOnes) {
			return fromBinary(new MemoryStream(data.ToExactByteArray()), N, df1, df2, df3Ones, df3NegOnes);
		}

		public static ProductFormPolynomial fromBinary(Stream @is, int N, int df1, int df2, int df3Ones, int df3NegOnes) {
			SparseTernaryPolynomial f1;

			f1 = SparseTernaryPolynomial.fromBinary(@is, N, df1, df1);
			SparseTernaryPolynomial f2 = SparseTernaryPolynomial.fromBinary(@is, N, df2, df2);
			SparseTernaryPolynomial f3 = SparseTernaryPolynomial.fromBinary(@is, N, df3Ones, df3NegOnes);

			return new ProductFormPolynomial(f1, f2, f3);
		}

		public virtual IByteArray toBinary() {
			IByteArray f1Bin = this.f1.toBinary();
			IByteArray f2Bin = this.f2.toBinary();
			IByteArray f3Bin = this.f3.toBinary();

			IByteArray all = FastArrays.CopyOf(f1Bin, f1Bin.Length + f2Bin.Length + f3Bin.Length);

			all.CopyFrom(f2Bin, 0, f1Bin.Length, f2Bin.Length);
			all.CopyFrom(f2Bin, 0, f1Bin.Length + f2Bin.Length, f3Bin.Length);

			f1Bin.Return();
			f2Bin.Return();
			f3Bin.Return();

			return all;
		}

		public override int GetHashCode() {
			const int prime  = 31;
			int       result = 1;
			result = (prime * result) + (this.f1 == null ? 0 : this.f1.GetHashCode());
			result = (prime * result) + (this.f2 == null ? 0 : this.f2.GetHashCode());
			result = (prime * result) + (this.f3 == null ? 0 : this.f3.GetHashCode());

			return result;
		}

		public override bool Equals(object obj) {
			if(this == obj) {
				return true;
			}

			if(obj == null) {
				return false;
			}

			if(this.GetType() != obj.GetType()) {
				return false;
			}

			ProductFormPolynomial other = (ProductFormPolynomial) obj;

			if(this.f1 == null) {
				if(other.f1 != null) {
					return false;
				}
			} else if(!this.f1.Equals(other.f1)) {
				return false;
			}

			if(this.f2 == null) {
				if(other.f2 != null) {
					return false;
				}
			} else if(!this.f2.Equals(other.f2)) {
				return false;
			}

			if(this.f3 == null) {
				if(other.f3 != null) {
					return false;
				}
			} else if(!this.f3.Equals(other.f3)) {
				return false;
			}

			return true;
		}
	}

}