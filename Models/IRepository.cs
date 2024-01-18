using System;
using System.Linq;
using System.Linq.Expressions;

namespace STB.MAP.UI.Utility
{
    public interface IRepository<TEntity> where TEntity : class
    {
        IQueryable<TEntity> GetAll(Expression<Func<TEntity, bool>>? filter = null, Func<IQueryable<TEntity>, IOrderedQueryable<TEntity>>? orderBy = null, string includeProperties = "");
        TEntity Get(Expression<Func<TEntity, bool>> filter);
        void Ekle(TEntity entity);
        void Guncelle(TEntity entity);
        void Sil(TEntity entity);
        void Kaydet();
    }
}

